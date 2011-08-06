#!/usr/bin/env perl -w

# The original script was a U.S. Government work and is such
# noncopyrighted, see: 
# http://en.wikipedia.org/wiki/Copyright_status_of_work_by_the_U.S._government
#   by
#   Scott Rose, NIST
#   8/7/09
# Modifications are Copyright (C) 2011  Blackstone Technology Group
#   by
#   Richard Bullington-McGuire <rbullington-mcguire@bstonetech.com>
#   7/29/2011

# This script originally used the Net::DNS::Sendmail module, but it is not in CPAN,
# and the only description of it out there on Softpedia
# http://linux.softpedia.com/get/Programming/Libraries/Net-DNS-Sendmail-21423.shtml
# does not lead to a real download of it.
# So instead of using that, we use the more standard Email::Sender module.
# Sending email directly to recipients SMTP servers tends to be buggy, anyway,
# in this age of spammers, whitelists, SPF records, and such.
#use Net::DNS::Sendmail;


use strict;
use Email::Sender::Simple qw(sendmail);
use Email::Simple;
use Email::Simple::Creator;
use Getopt::Long;
use JSON::PP;
use Net::DNS;
use Net::DNS::Resolver;
use Net::DNS::RR::DS;
use Net::DNS::SEC;
use Time::Local;

sub what_happened($$$$);
sub send_report($$$$$$);

sub main() {
my $name;
my @line; 
my $signed;
my $valid;
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
my @problemzones;
my @islands;
my @problems;
my $p = -1;
my $is = -1;

my ($help, $sender, $recipient, $zoneFile, $activityFile, @activity);

usage() if ( !  GetOptions(
	'help|?' => \$help, 
	'sender=s' => \$sender, 
	'recipient=s' => \$recipient, 
	'zonefile=s' => \$zoneFile, 
	'activityfile=s' =>\$activityFile)
		or defined $help );

sub usage {
	print "Unknown option: @_\n" if ( @_ );
	print "usage: DNSSECListWalk.pl [--zone-file FILE] \n\t[--activity-file FILE] [-sender EMAIL] [-recipient EMAIL] [--help|-?]\n";
	exit 0;
}

#declare some variables now
$zoneFile = "test-zones.txt" unless defined $zoneFile;
$recipient = "bob\@example.com" unless defined $recipient;
$sender = "alice\@example.net" unless defined $sender;

my ($activityData, %globalClicks);
if (defined $activityFile) {
	my $activity= do { local( @ARGV, $/ ) = $activityFile ; <> } ;
	$activityData = decode_json($activity);
	#print "$activityData->[0]{'agency'}\t$activityData->[0]{'global_clicks'}\n";
	foreach my $click (@$activityData) {
		$globalClicks{$$click{'agency'}} = $$click{'global_clicks'};
		#print "click $click a $$click{'agency'} g $$click{'global_clicks'} gc $globalClicks{$$click{'agency'}}\n"
	}
}

open(LIST, $zoneFile) || die "Cannot open zone input file";
open(OUTPUT, ">DNSSECListStatus.html") || die "Cannot open output file";


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
print OUTPUT ("<TD ALIGN = \"center\"> Site Visits </TD> \n") if %globalClicks;
print OUTPUT ("<TD ALIGN = \"center\"> Signed? </TD> \n");
print OUTPUT ("<TD ALIGN = \"center\"> Status </TD> \n");
print OUTPUT ("<TD ALIGN = \"center\"> Island or Chain? </TD> \n");
#print OUTPUT ("<TD ALIGN = \"center\"> PMTU Report </TD> \n");
print OUTPUT ("</TR> \n");


while (<LIST>) {
	my ($zone) = split(/\t/, $_);
	my $reply = Net::DNS::Packet->new(); 

	my $signed = 0;
	my $valid = 0;

	print OUTPUT ("<TR> <TD> " . $zone . "</TD> ");
    print OUTPUT ("<TD ALIGN = \"right\">$globalClicks{$zone}</FONT> </TD> \n") if %globalClicks;
	my $numVisits += $globalClicks{$zone} if %globalClicks;
	#DNSKEY query for signed/unsigned	
	$testRes->dnssec(1);
	$reply = $testRes->send($zone, 'DNSKEY');
	if ($reply ne undef) {
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
			$problemzones[++$p] = $zone;
			$reply = $testRes->send($zone, 'DNSKEY');	
				if ($reply ne undef) {
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
					$problems[$p] = what_happened($testRes, $reply, $zone, $totalErr);
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
	if ($reply ne undef) {
		my $headerc = Net::DNS::Header->new;
		$headerc = $reply->header;
		if ($headerc->rcode eq "NOERROR") {
			my $ansSec = $headerc->ancount;
			if ($ansSec > 0) {
				print OUTPUT ("<TD ALIGN = \"center\"BGCOLOR=\"#008000\"><FONT COLOR=\"#FFFFFF\">Chain</FONT> </TD> \n");
				$islands[++$is] = $zone;
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

	#now do dnsfunnel test

	 print OUTPUT ("</TR>\n");
}

	print OUTPUT ("<TR><TD ALIGN=\"center\"><b>Totals:</b></TD>");
	print OUTPUT ("<TD ALIGN = \"center\">" . $numVisits . " </TD> \n") if %globalClicks;
	print OUTPUT ("<TD ALIGN=\"center\">" . $numSigned . "</TD>");
	print OUTPUT ("<TD ALIGN=\"center\">" . $numValid . "</TD>");
	print OUTPUT ("<TD ALIGN=\"center\">" . $numChained . "</TD>");

print OUTPUT ("</TABLE> <br> <HR> \n");
print OUTPUT ("<BR></P></BODY></HTML>\n");


send_report($p, \@problemzones, \@problems, $sender, $recipient, $totalErr);
}

sub send_report($$$$$$) {
    my ($p, $problemzones, $problems, $sender, $recipient, $totalErr) = @_;
	#now send a report to admin
	if ($p > 0) {
		my $body = "$p zones with potential problems:\n";
		for (my $i=0; $i<$p; $i++) {
			$body .= @$problemzones[$i] . " " . @$problems[$i] . "\n";
		}
		#now put in the totals of errors
		$body .= "==============================\n\n";
		$body .= $$totalErr{'NOSIG'} . "\t" . $$totalErr{'EXPIRED'} . "\t" . $$totalErr{'INCEPT'} . "\t" . $$totalErr{'BADROLL'} . "\t" . $$totalErr{'DSPREPUB'} . "\t" . $$totalErr{'OTHER'} . "\n";

		my $email = Email::Simple->create(
			header => [
				From =>  $sender,
				To => $recipient,
				Subject => "Today's DNSSEC FAIL",
			],
			body => $body,
		);
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

