class Hiera
    module Backend
        class Yamlgpg_backend
            def initialize
                require 'yaml'
                require 'gpgme'

                homes = ["HOME", "HOMEPATH"]
                real_home = homes.detect { |h| ENV[h] != nil }

                key_dir = Config[:yamlgpg][:key_dir] || "#{ENV[real_home]}/.gnupg"
                ENV["GNUPGHOME"]=key_dir
                Hiera.debug("Hiera yamlgpg backend starting")
            end

            def lookup(key, scope, order_override, resolution_type)
                answer = nil

                Hiera.debug("Looking up #{key} in yamlgpg backend")

                Backend.datasources(scope, order_override) do |source|
                    Hiera.debug("Looking for data source #{source}")

                    yamlfile = Backend.datafile(:yamlgpg, scope, source, "yaml") || next

                    data = YAML.load_file(yamlfile)

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
                    rescue Exception => e
                        # If there are any exceptions with decryption, then we go on so that
                        # other backends might find a non-encrypted value
                        Hiera.debug(e)
                        next
                    end
                end

                return answer
            end

            def decrypt_any(d)
                if d.kind_of? String
                    if d.start_with?("-----BEGIN PGP MESSAGE-----\n\n")
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
                    raise Exception, "Expected String, Array, or Hash, got #{d.class}"
                end
            end

            def decrypt_ciphertext(ciphertext)
                ctx = GPGME::Ctx.new

                if !ctx.keys.empty?
                    raw = GPGME::Data.new(ciphertext)

                    begin
                        txt = ctx.decrypt(raw)
                    rescue GPGME::Error::DecryptFailed => e
                        raise Exception, "Warning: GPG Decryption failed, check your GPG settings"
                    rescue => e
                        raise Exception, "Warning: General exception decrypting GPG file"
                    end

                    txt.seek 0
                    return txt.read
                else
                    raise Exception, "No usable keys found in #{ENV['GNUPGHOME']}. Check :key_dir value in hiera.yaml is correct"
                end
            end
        end
    end
end
