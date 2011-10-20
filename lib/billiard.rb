#!  /usr/bin/env ruby
#
#   Billiard 0.1
#   vim: bg=dark

require 'socket'
require 'thread'

FRIENDS_BY_IP = %w[172.16.0.2]

class INSocket
    def initialize sck
        @sck  = sck
        @svnm = 'SRVM'
        @tmnl = 'TERMINAL'
        @user = 'USERNAME'
        @trc  = 1
        @kyu  = Queue.new
        @thd  = Thread.new {send_items(@kyu, @sck)}
        @htb  = Thread.new {send_keep_alive}
    end

    def send_keep_alive
        while true
            sleep 120
            @kyu << ['`SC`0004HBHBB7BDB7BD', proc {|x| }]
        end
    end

    def fetch_ack sck
        got = sck.read(8)
        STDERR.print('>>> ' + got)
        len = got[4, 4].to_i(16)
        got = sck.read(len)
        STDERR.print got
        gat = sck.read(8)
        STDERR.puts gat
        got[37 .. -1]
    end

    def send_items kyu, sck
        while true
            got = kyu.pop
            STDERR.puts(%[IN>>> #{got.first}])
            sck.write(got.first)
            sck.flush
            ans = fetch_ack sck
            got.last.call ans
            #   Thread.new {got.last.call(fetch_ack(sck))}
        end
    end

    def next_trans_id
        it = @trc
        @trc = @trc + 1
        it
    end

    def make_checksum str
        rez = "\0\0\0\0"
        pos = 0
        while pos < str.length
            rez[0] = rez[0] ^ str[pos]
            rez[1] = rez[1] ^ str[pos + 1]
            rez[2] = rez[2] ^ str[pos + 2]
            rez[3] = rez[3] ^ str[pos + 3]
            pos = pos + 4
        end
        rez[0] = ~rez[0]
        rez[1] = ~rez[1]
        rez[2] = ~rez[2]
        rez[3] = ~rez[3]
        rez.split('').map {|x| ('%2X' % [x[0]]).gsub(/\s/, '0')}.join
    end

    def send cmd, stp = nil, ctl = 'Con', &blk
        raise ArgumentError.new(%[Who handles the result?]) unless block_given?
        t1 = %[#{@tmnl}        ][0, 8]
        s1 = %[#{stp || @svnm}        ][0, 8]
        msghdr = %[1.00#{t1}#{s1}]
        c1 = %[#{ctl}Con][0, 3].upcase
        seshdr = %[00000001DLG#{c1}0000]
        trshdr = %[%sTXBEG 0000] % [('%8X' % [next_trans_id]).gsub(/\s/, '0')]
        lack   = cmd.length % 4
        oprmsg = if lack.zero? then
                     cmd
                 else
                     cmd + (' ' * (4 - lack))
                 end
        tailer = %[#{msghdr}#{seshdr}#{trshdr}#{oprmsg}]
        msgln  = tailer.length
        chksm  = make_checksum(tailer)
        rez    = '`SC`%s%s%s' % [('%4X' % [msgln]).gsub(/\s/, '0'), tailer, chksm[0, 8]]
        @kyu << [rez, blk]
    end

    def authenticate svid, tmnl, user, pwd
        @svnm = svid
        @tmnl = tmnl
        @user = user
        send(%[LOGIN:PSWD=#{pwd[0, 8]},USER=#{user[0, 8]}], 'SRVM', 'LGN') do |rez|
            raise Exception.new(%[Invalid auth]) unless rez =~ /succeeded/i
        end
    end

    def run_requests port
        TCPServer.open(port) do |srv|
            while true
                con = srv.accept
                _, __, fhst, fip = con.peeraddr
                unless FRIENDS_BY_IP.member?(fip) then
                    STDERR.puts(%[Access denied: #{fhst} (#{fip})])
                    con.puts(%[Access denied.])
                    con.close
                else
                    Thread.new do
                        STDERR.puts(%[Client [#{fhst} (#{fip}) #{Time.now}] connected ...])
                        con.each_line do |ln|
                            got = ln.chomp
                            STDERR.puts(%[>>> #{fhst} (#{fip}) #{Time.now} >>>] + got)
                            send(got, 'EPPC') do |rez|
                                con.write((%[%s] % [('%4X' % [rez.length]).gsub(/\s/, '0')]) + rez)
                                STDERR.puts(%[<<< #{fhst} (#{fip}) #{Time.now} <<<] + rez)
                            end
                        end
                        con.close
                        STDERR.puts(%[... client [#{fhst} (#{fip}) #{Time.now}] disconnected.])
                    end
                end
            end
        end
    end

    def close
        send(%[LOGOUT:USER=#{@user[0, 8]}], 'SRVM') do |rez|
            STDOUT.puts(%[Logged out.])
        end
        @sck.flush
        @sck.close
    end
end

class INConnection
    def initialize inhst, inprt
        TCPSocket.open(inhst, inprt) do |srv|
            inc = INSocket.new srv
            yield(inc)
            inc.close
        end
    end
end

def bmain args
    if args.length < 7 then
        STDERR.puts(%[#{$0} in-host in-port billiard-port service-id terminal user password])
        return 1
    end
    INConnection.new(args.first, args[1].to_i) do |inc|
        inc.authenticate(args[3], args[4], args[5], args[6])
        inc.run_requests(args[2].to_i)
    end
    return 0
end

exit(bmain(ARGV))
