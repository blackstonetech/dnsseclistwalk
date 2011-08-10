#!/usr/bin/env perl

# DNSSECListWalk
# Originally by
#   Scott Rose, NIST
#   8/7/09
#
# The original script was a U.S. Government work and is such
# noncopyrighted in the U.S. (effectively public domain), see: 
#  http://en.wikipedia.org/wiki/Copyright_status_of_work_by_the_U.S._government
# Modifications are Copyright (C) 2011  Blackstone Technology Group
#   - Richard Bullington-McGuire <rbullington-mcguire@bstonetech.com>
#   7/29/2011

package Local::DNSSECListWalk;

use strict;
use warnings;
# This script originally used the Net::DNS::Sendmail module, but it is not in CPAN,
# and the only description of it out there on Softpedia
# http://linux.softpedia.com/get/Programming/Libraries/Net-DNS-Sendmail-21423.shtml
# does not lead to a real download of it.
# So instead of using that, we use the more standard Email::Sender module.
# Sending email directly to recipients SMTP servers tends to be buggy, anyway,
# in this age of spammers, whitelists, SPF records, and such.
#use Net::DNS::Sendmail;

use Email::Sender::Simple qw(sendmail);
use Email::Simple;
use Email::Simple::Creator;
use File::Basename;
use Getopt::Long;
use JSON::PP;
use Net::DNS;
use Net::DNS::Resolver;
use Net::DNS::RR::DS;
use Net::DNS::SEC;
use Time::Local;
use Template;

my $dirname = dirname(__FILE__);
my $tt = Template->new({
		INCLUDE_PATH => "$dirname/templates", 
		INTERPOLATE  => 0,
}) || die "$Template::ERROR\n";

__PACKAGE__->main() unless caller;

# send a report to the administrator regarding failures
sub send_report($$$$) {
	my ($problems, $sender, $recipient, $totalErr) = @_;
	#print "send report for $problems count $#$problems\n";
	#print encode_json $problems;
	if ($#$problems > 0) {
		my $vars = { 
			'problems' => $problems,
			'totalErr' => $totalErr,
		};
		my $body = '';
		$tt->process('email.tmpl', $vars, \$body) || die $tt->error(), '\n';
		my $email = Email::Simple->create(
			header => [
				From =>  $sender,
				To => $recipient,
				Subject => "Today's DNSSEC FAIL",
			],
			body => $body,
		);
		#print $email->as_string();
		sendmail($email);
	}
}

sub what_happened($$$$) {
	my ($testRes, $resp, $zone, $totalErr) = @_;
	my $sigExpire;
	my $sigIncep;
	my @keyRRs;
	my @keyResp = $resp->answer;
	#get the keys in a separate array and its signature's expiration
	my @inct=gmtime(time);
	my $foundSIG = 0;
	my $currentdatestring=  sprintf ("%d%02d%02d%02d%02d%02d",
					 $inct[5]+1900 ,$inct[4]+1 , 
					 $inct[3] ,$inct[2] , $inct[1]  ,
					 $inct[0]);	
	my $header = Net::DNS::Header->new;
		$header = $resp->header; 
	if ($header->rcode eq "NOERROR") {
		foreach my $respAns (@keyResp) {
			my $theType = $respAns->type;
			if ($theType eq "DNSKEY") {
				$keyRRs[++$#keyRRs] = $respAns;
			} elsif ($theType eq "RRSIG") {
				$foundSIG = 1;
				$sigExpire = $respAns->sigexpiration;
				$sigIncep = $respAns->siginception;			
				if ($currentdatestring gt $sigExpire) {
					$$totalErr{'EXPIRED'}++;
					return "SIGs expired.";
				} elsif ($currentdatestring lt $sigIncep) {
					$$totalErr{'INCEPT'}++;
					return "SIGs not valid yet.";
				}
			}
		}
		if ($foundSIG == 0) {
			$$totalErr{'NOSIG'}++;
			return "No SIGs.";
		}
		
		#get the DS RR
		my $DSreply = $testRes->send($zone, 'DS');
		if ($DSreply ne undef) {
			my $headerc = Net::DNS::Header->new;
			$headerc = $DSreply->header;
			if ($headerc->rcode eq "NOERROR") {
				my @ansSec = $DSreply->answer;
				my $match = 0;
				my $inuse = 0;					
				foreach my $ansRR (@ansSec) {
					my $theT = $ansRR->type;
					if ($theT eq "DS") {
						my $DSRR = $ansRR;
						my $DSkeytag = $ansRR->keytag;
						foreach my $aK (@keyRRs) {
							if (($aK->keytag) eq $DSkeytag) {
								$match = 1;
								#now make sure it's not the pre-published one
								foreach my $respAns (@keyResp) {
									my $theType = $respAns->type;
									if ($theType eq "RRSIG") {
										if (($respAns->keytag) eq $DSkeytag) {
											$inuse = 1;
										}
									}
								}
							}
						}
					}
				}
				if ($match == 0) {
					$$totalErr{'BADROLL'}++;
					return "Bad KSK rollover";
				} elsif ($inuse == 0) {
					$$totalErr{'DSPREPUB'}++;
					return "DS points to pre-published key";
				}
			}
		}
	}
	$$totalErr{'OTHER'}++;
	return "Some other strange error occurred";				
}

sub parseOptions() {
	my ($help, $sender, $recipient, $zoneFile, $activityFile, $outputFile);

	usage() if ( !  GetOptions(
		'help|?' => \$help, 
		'sender=s' => \$sender, 
		'recipient=s' => \$recipient, 
		'zonefile=s' => \$zoneFile, 
		'activityfile=s' =>\$activityFile, 
		'outputFile=s' =>\$outputFile)
			or defined $help );

	sub usage {
		print "Unknown option: @_\n" if ( @_ );
		print "usage: DNSSECListWalk.pl [--zone-file FILE] \n\t[--activity-file FILE] [--output-file FILE] [-sender EMAIL] [-recipient EMAIL] [--help|-?]\n";
		exit 0;
	}

	$zoneFile = "test-zones.txt" unless defined $zoneFile;
	$recipient = "bob\@example.com" unless defined $recipient;
	$sender = "alice\@example.net" unless defined $sender;
	$outputFile = "DNSSECListStatus.html" unless defined $outputFile;
	return ($help, $sender, $recipient, $zoneFile, $activityFile, $outputFile);
}

sub getGlobalClicks($) {
	my ($activityFile) = @_;
	my $globalClicks;
	if (defined $activityFile) {
		my $activity = do { local( @ARGV, $/ ) = $activityFile ; <> } ;
		my $activityData = decode_json($activity);
		$globalClicks = {};
		foreach my $click (@$activityData) {
			$$globalClicks{$$click{'agency'}} = $$click{'global_clicks'};
			#print "click $click a $$click{'agency'} g $$click{'global_clicks'} gc $$globalClicks{$$click{'agency'}}\n"
		}
	}
	return ($globalClicks);
}

sub main() {
	my @line; 
	my $numValid = 0;
	my $numChained = 0;
	my $numSigned = 0;
	my $numVisits = 0;
	my $totalErr = { 
		'NOSIG' => 0,
		'EXPIRED' => 0,
		'INCEPT' => 0,
		'BADROLL' => 0,
		'DSPREPUB' => 0,
		'OTHER' => 0,
	};
	my $problems = [];
	my $p = -1;

	my ($help, $sender, $recipient, $zoneFile, $activityFile, $outputFile) = parseOptions();


	my ($globalClicks) = getGlobalClicks($activityFile);

	open(LIST, $zoneFile) || die "Cannot open zone input file";
	open(OUTPUT, ">$outputFile") || die "Cannot open output file";

	my $testRes = Net::DNS::Resolver->new();

	print OUTPUT ("<HTML><HEAD>\n");
	print OUTPUT ("<TITLE>DNSSEC Deployment Status</TITLE></HEAD>");
	print OUTPUT ("<BODY LANG=\"en-US\" DIR=\"LTR\"> <H1>DNSSEC Deployment Status</H1>");
	print OUTPUT ("<p>This is the current snapshot of the state of DNSSEC deployment in a selection of domains.");

	print OUTPUT ("<p>In the table below:</p>"); 
	print OUTPUT ("<p><b>Signed</b> column indicates that the zone has DNSSEC RRs present or not (i.e. RRSIGs are returned in a response.</p>");
	print OUTPUT ("<p><b>Status</b> column indicates whether or not the signatures are valid, or if there is some sort of error that would cause validation to fail.  Not having a signed delegation from .gov does not mean failure in this test.</p>");
	print OUTPUT ("<p><b>Island/Chained</b> column indicates if the zone has a secure delegation (i.e. a DS RR) from its parent zone,");
	print OUTPUT ("usually the top-level TLD or a second-level.</p>"); 

	print OUTPUT ("<p><b>NOTE:</b> zones that are no longer present are the zones with <b>\"Error\"</b> in the last column.</p>");
	print OUTPUT ("<p>Time: " . localtime() . "</p>");
	print OUTPUT ("<TABLE BORDER=\"4\" CELLSPACING=\"4\" CELLPADDING=\"5\"> \n");
	print OUTPUT ("<CAPTION>Zone Status</CAPTION>");
	print OUTPUT ("<TR> <TD ALIGN = \"center\"> Zonename </TD> \n");
	print OUTPUT ("<TD ALIGN = \"center\"> Site Visits </TD> \n") if $globalClicks;
	print OUTPUT ("<TD ALIGN = \"center\"> Signed? </TD> \n");
	print OUTPUT ("<TD ALIGN = \"center\"> Status </TD> \n");
	print OUTPUT ("<TD ALIGN = \"center\"> Island or Chain? </TD> \n");
	#print OUTPUT ("<TD ALIGN = \"center\"> PMTU Report </TD> \n");
	print OUTPUT ("</TR> \n");


	while (<LIST>) {
		my ($zone) = split(/\t/, $_);
		chomp $zone;
		my $reply = Net::DNS::Packet->new(); 

		my $signed = 0;
		my $valid = 0;

		print OUTPUT ("<TR> <TD> " . $zone . "</TD> ");
		if ($globalClicks) {
			#print "globalClicks defined while processing $zone\n";
			my $zoneVisits = '';
			if (exists $$globalClicks{$zone}) {
				$zoneVisits = $$globalClicks{$zone};
				$numVisits += $zoneVisits;
				#print "zone $zone zoneVisits $zoneVisits numVisits $numVisits\n";
			}
			print OUTPUT ("<TD ALIGN = \"right\">$zoneVisits</FONT> </TD> \n") 
		}
		#DNSKEY query for signed/unsigned	
		$testRes->dnssec(1);
		$reply = $testRes->send($zone, 'DNSKEY');
		if ($reply) {
			my $header = Net::DNS::Header->new;
			$header = $reply->header;
			if ($header->rcode eq "NOERROR") {
				my $ansSec = $header->ancount;
				if ($ansSec > 0) {
					$signed = 1;
					$valid = 1;
					$numSigned++;
					$numValid++;
				}  else {
					$signed = 0;
				}
			} elsif ($header->rcode eq "SERVFAIL") {
				$testRes->cdflag(1);
				my $problem = { 'zone' => $zone };
				push @$problems, $problem;
				$reply = $testRes->send($zone, 'DNSKEY');	
					if ($reply) {
						my $headerv = Net::DNS::Header->new;
						$headerv = $reply->header;
						if ($headerv->rcode eq "NOERROR") {
							my $ansSec = $headerv->ancount;
							if ($ansSec > 0) {
								$signed = 1;
								$valid = 0;
								$numSigned++;	 
							} else {
								$signed = 0;
								$valid = 0;
							}
						}
						$problem->{'description'} = what_happened($testRes, $reply, $zone, $totalErr);
					}
			} 
		} else {
			$signed = 0;
			$valid = 0;
		}

		$testRes->cdflag(0);
		if ($signed eq 1) {
			print OUTPUT ("<TD ALIGN = \"center\" BGCOLOR=\"#008000\"><FONT COLOR=\"#FFFFFF\">Signed</FONT> </TD> \n");
			if ($valid eq 1) {
				print OUTPUT ("<TD ALIGN = \"center\"BGCOLOR=\"#008000\"><FONT COLOR=\"#FFFFFF\">Valid</FONT> </TD> \n");
			} else {
				print OUTPUT ("<TD ALIGN = \"center\"BGCOLOR=\"#FF0000\"><FONT COLOR=\"#FFFFFF\"><a href=\"http://dnsviz.net/search/?d=" . $zone . "\">Error</a></FONT> </TD> \n");
			}
		} else {
			print OUTPUT ("<TD ALIGN = \"center\" BGCOLOR=\"#FF0000\"><FONT COLOR=\"#FFFFFF\">Unsigned</FONT> </TD> \n");
			print OUTPUT ("<TD ALIGN = \"center\">N/A</FONT> </TD> \n");
		}
		
		#Test for Chain/Island
		$reply = $testRes->send($zone, 'DS');
		if ($reply) {
			my $headerc = Net::DNS::Header->new;
			$headerc = $reply->header;
			if ($headerc->rcode eq "NOERROR") {
				my $ansSec = $headerc->ancount;
				if ($ansSec > 0) {
					print OUTPUT ("<TD ALIGN = \"center\"BGCOLOR=\"#008000\"><FONT COLOR=\"#FFFFFF\">Chain</FONT> </TD> \n");
					$numChained++;
				}  else {
					if ($signed == 1) {
						print OUTPUT ("<TD ALIGN = \"center\">Island</FONT> </TD> \n");
					} else {
						print OUTPUT ("<TD ALIGN = \"center\">N/A</FONT> </TD> \n");
					}
				}
			} else {
				print OUTPUT ("<TD ALIGN = \"center\">Error</FONT> </TD> \n");
			}
		} else {
			print OUTPUT ("<TD ALIGN = \"center\">Error</FONT> </TD> \n");
		}
		print OUTPUT ("</TR>\n");
	}

	print OUTPUT ("<TR><TD ALIGN=\"center\"><b>Totals:</b></TD>");
	print OUTPUT ("<TD ALIGN = \"center\">" . $numVisits . " </TD> \n") if $globalClicks;
	print OUTPUT ("<TD ALIGN=\"center\">" . $numSigned . "</TD>");
	print OUTPUT ("<TD ALIGN=\"center\">" . $numValid . "</TD>");
	print OUTPUT ("<TD ALIGN=\"center\">" . $numChained . "</TD>");

	print OUTPUT ("</TABLE> <br> <HR> \n");
	print OUTPUT ("<BR></P></BODY></HTML>\n");


	send_report($problems, $sender, $recipient, $totalErr);
}

