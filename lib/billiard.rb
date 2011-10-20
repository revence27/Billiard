#!  /usr/bin/env ruby
#
#   Billiard 0.1
#   vim: bg=dark

require 'rubygems'
require 'json'
require 'set'
require 'socket'
require 'thread'

class INSocket
    def initialize sck, friends
        @sck  = sck
        @frds = friends
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
        $stderr.print('>>> ' + got)
        len = got[4, 4].to_i(16)
        got = sck.read(len)
        $stderr.print got
        gat = sck.read(8)
        $stderr.puts gat
        got[37 .. -1]
    end

    def send_items kyu, sck
        while true
            got = kyu.pop
            $stderr.puts(%[IN>>> #{got.first}])
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
                unless @frds.member?(fip) then
                    $stderr.puts(%[Access denied: #{fhst} (#{fip})])
                    con.puts(%[Access denied.])
                    con.close
                else
                    Thread.new do
                        $stderr.puts(%[Client [#{fhst} (#{fip}) #{Time.now}] connected ...])
                        con.each_line do |ln|
                            got = ln.chomp
                            $stderr.puts(%[>>> #{fhst} (#{fip}) #{Time.now} >>>] + got)
                            send(got, 'EPPC') do |rez|
                                con.write((%[%s] % [('%4X' % [rez.length]).gsub(/\s/, '0')]) + rez)
                                $stderr.puts(%[<<< #{fhst} (#{fip}) #{Time.now} <<<] + rez)
                            end
                        end
                        con.close
                        $stderr.puts(%[... client [#{fhst} (#{fip}) #{Time.now}] disconnected.])
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
    def initialize inhst, inprt, friends
        TCPSocket.open(inhst, inprt) do |srv|
            inc = INSocket.new(srv, Set.new(friends))
            yield(inc)
            inc.close
        end
    end
end

def bmain args
    args << %[/etc/billiard/conf.js] if args.empty?
    File.open(args.first) do |f|
        cnf = JSON.parse(f.read)
        if cnf['logfile'] then
            $stderr = File.open(cnf['logfile'], 'a')
        end
        INConnection.new(cnf['in']['host'], cnf['in']['port'], cnf['service']['friends']) do |inc|
            inc.authenticate(cnf['service']['id'], cnf['service']['terminal'], cnf['in']['user'], cnf['in']['password'])
            inc.run_requests(cnf['service']['port'])
        end
    end
    0
rescue Exception => e
    $stderr.puts(e.inspect, *e.backtrace)
    1
end

exit(bmain(ARGV))
