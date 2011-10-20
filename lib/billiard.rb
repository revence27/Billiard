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
    def initialize sck, frds
        @sck  = sck
        @frds = frds
        @svnm = 'SRVM'
        @tmnl = 'TERMINAL'
        @user = 'USERNAME'
        @kyu  = Queue.new
        @trc  = 1
        @trm  = Mutex.new
        @mut  = Mutex.new
        @rqs  = {'0' => proc {|x|}}
        @thd  = Thread.new {send_items(@kyu, @sck, @mut)}
        @rcv  = Thread.new {recv_items(@kyu, @sck, @mut)}
        @htb  = Thread.new {send_keep_alive}
    end

    def send_keep_alive
        while true
            sleep 120
            @kyu << ['`SC`0004HBHBB7BDB7BD', 0, {:exec => proc {|x| }}]
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
        if len == 4 then
            #   Heartbeat.
            ['', 0]
        else
            ans = got[37 .. -1]
            tid = got.match(/Dlg.{7}(.{8})/i)[1].to_i(16)
            [ans, tid]
        end
    end

    def recv_items kyu, sck, mut
        while true
            ans, tid = fetch_ack sck
            mut.synchronize do
                Thread.new do
                    begin
                        hdlr = @rqs.delete(tid.to_s)
                        if hdlr then
                            if hdlr[:exec] then
                                hdlr[:exec].call(ans)
                            elsif hdlr[:socket] then
                                con = hdlr[:socket]
                                con.write((%[%s] % [('%4X' % [ans.length]).gsub(/\s/, '0')]) + ans)
                                _, _, fhst, fip = con.peeraddr
                                $stderr.puts(%[<<< #{fhst} (#{fip}) #{Time.now}\n<<<] + ans)
                            else
                                raise ArgumentError.new(%[Handler #{hdlr.inspect} not understood.])
                            end
                            $stderr.puts(%[[[Response for transaction %d:#{hdlr.inspect}]]] % [tid])
                        else
                            $stderr.puts(%[Transaction #{tid} no exist!])
                        end
                    rescue Exception => e
                        $stderr.puts(e.inspect, *e.backtrace)
                    end
                end
            end
        end
    end

    def send_items kyu, sck, mut
        while true
            got = kyu.pop
            $stderr.puts(%[IN>>> #{got.first}])
            sck.write(got.first)
            sck.flush
            $stderr.puts(%[[[Transaction %d:#{got.last}]]] % [got[1]])
            mut.synchronize do
                @rqs[got[1].to_s] = got.last
            end
        end
    end

    def next_trans_id
        it = @trc
        @trm.synchronize do
            it = @trc
            @trc = @trc + 1
        end
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

    def send cmd, stp = nil, ctl = 'Con', con = nil
        hdl = if not con then
            raise ArgumentError.new(%[Who handles the result?]) unless block_given?
            {:exec => proc {|x| yield(x)}}
        else
            con
        end
        t1 = %[#{@tmnl}        ][0, 8]
        s1 = %[#{stp || @svnm}        ][0, 8]
        c1 = %[#{ctl}Con][0, 3].upcase
        msghdr = %[1.00#{t1}#{s1}]
        seshdr = %[00000001DLG#{c1}0000]
        tid    = next_trans_id
        trshdr = %[%sTXBEG 0000] % [('%8X' % [tid]).gsub(/\s/, '0')]
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
        @kyu << [rez, tid, hdl]
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
                    Thread.new(con) do |ncon|
                        begin
                            $stderr.puts(%[Client [#{fhst} (#{fip}) #{Time.now}] connected ...])
                            ncon.each_line do |ln|
                                got = ln.chomp
                                if got.strip.empty? then
                                    nil
                                else
                                    $stderr.puts(%[>>> #{fhst} (#{fip}) #{Time.now} >>>] + got)
                                    send(got, 'EPPC', 'Con', {:socket => ncon})
                                end
                            end
                            ncon.close
                            $stderr.puts(%[... client [#{fhst} (#{fip}) #{Time.now}] disconnected.])
                        rescue Exception => e
                            $stderr.puts(%[Connection error for #{fhst}:#{fip} (#{e.inspect})])
                            ncon.close
                        end
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
    def initialize inhst, inprt, frds
        TCPSocket.open(inhst, inprt) do |srv|
            inc = INSocket.new(srv, Set.new(frds))
            yield(inc)
            inc.close
        end
    end
end

def bmain args
    args << %[/etc/billiard/conf.js] if args.empty?
    File.open(args.first) do |f|
        cnf = JSON.parse(f.read)
        $stderr = File.open(cnf['logfile'], 'a') if cnf['logfile']
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
