# TODO: Split this out into its own package

function hexdump!(out::IO, buf::Vector{UInt8})
    off = 1
    while off < length(buf)
        print(out, string(off, base=10, pad=4))
        print(out, ": ")
        off_range = off:off+15
        # Print HEX
        for idx = off_range
            if idx > length(buf)
                print(out, "  ")
            else
                print(out, string(buf[idx], base=16, pad=2))
            end
            print(out, ' ')
        end
        print(out, ' ')
        # Print ASCII
        for idx = off_range
            if idx < length(buf)
                byte = buf[idx]
                print(out, 32 <= byte <= 126 ? Char(byte) : '.')
            end
        end
        println(out)
        off += 16
    end
end
