class Hiera
    module Backend
        class YamlgpgError < StandardError
        end

        # A hiera backend to decrypt yaml values, inspiration and idea to use
        # gpgme comes from https://github.com/crayfishx/hiera-gpg and basic
        # structure comes from the builtin yaml hiera backend.
        class Yamlgpg_backend
            def initialize(cache=nil)
                require 'yaml'
                require 'gpgme'

                homes = ["HOME", "HOMEPATH"]
                real_home = homes.detect { |h| ENV[h] != nil }

                key_dir = Config[:yamlgpg][:key_dir] || "#{ENV[real_home]}/.gnupg"
                @fail = Config[:yamlgpg][:fail_on_error] || false

                GPGME::Engine.home_dir = key_dir
                @ctx = GPGME::Ctx.new
                @cache = cache || Filecache.new

                Hiera.debug("Hiera yamlgpg backend starting")
            end

            def lookup(key, scope, order_override, resolution_type)
                answer = nil

                Hiera.debug("Looking up #{key} in yamlgpg backend")

                Backend.datasources(scope, order_override) do |source|
                    Hiera.debug("Looking for data source #{source}")

                    yamlfile = Backend.datafile(:yamlgpg, scope, source, "yaml") || next

                    data = @cache.read(yamlfile, Hash, {}) do |data|
                        YAML.load(data)
                    end

                    next if ! data
                    next if data.empty?
                    next unless data.include?(key)

                    # for array resolution we just append to the array whatever
                    # we find, we then goes onto the next file and keep adding to
                    # the array
                    #
                    # for priority searches we break after the first found data item
                    new_answer = Backend.parse_answer(data[key], scope)

                    begin
                        case resolution_type
                        when :array
                            raise Exception, "Hiera type mismatch: expected Array and got #{new_answer.class}" unless new_answer.kind_of? Array or new_answer.kind_of? String
                            answer ||= []
                            answer << decrypt_any(new_answer)
                        when :hash
                            raise Exception, "Hiera type mismatch: expected Hash and got #{new_answer.class}" unless new_answer.kind_of? Hash
                            answer ||= {}
                            answer = decrypt_any(new_answer).merge answer
                        else
                            answer = decrypt_any(new_answer)
                            break
                        end
                    rescue YamlgpgError => e
                        # If there are any exceptions with decryption, then we go on so that
                        # other backends might find a non-encrypted value
                        Hiera.warn(e)
                      if @fail
                        raise e
                      else
                        next
                      end
                    end
                end

                return answer
            end

            def decrypt_any(d)
                if d.kind_of? String or d.kind_of? Fixnum
                    if d.to_s.match(/^-----BEGIN PGP MESSAGE-----[[:space:]]*\n/)
                        return decrypt_ciphertext(d)
                    else
                        return d
                    end
                elsif d.kind_of? Array
                    return d.map{|v| decrypt_any(v)}
                elsif d.kind_of? Hash
                    d.each_key{|k| d[k] = decrypt_any(d[k])}
                    return d
                else
                    raise YamlgpgError, "Expected String, Array, or Hash, got #{d.class}"
                end
            end

            def decrypt_ciphertext(ciphertext)
                if @ctx.keys.empty?
                    raise YamlgpgError, "No usable keys found in #{GPGME::Engine.info.first.home_dir}. Check :key_dir value in hiera.yaml is correct"
                end

                begin
                    txt = @ctx.decrypt(GPGME::Data.new(ciphertext))
                rescue GPGME::Error::DecryptFailed => e
                    raise YamlgpgError, "GPG Decryption failed, check your GPG settings: #{e}"
                rescue Exception => e
                    raise YamlgpgError, "General exception decrypting GPG file: #{e}"
                end

                txt.seek 0
                return txt.read
            end
        end
    end
end
