# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME
Mail::SpamAssassin::Prelude - SpamAssassin Prelude logging module
=head1 SYNOPSIS
  use Mail::SpamAssassin::Prelude;
=head1 AUTHOR
CSSI (Prelude Team)
=cut

package Mail::SpamAssassin::Prelude;

use strict;
use warnings;
use Prelude;
use bytes;

use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);

BEGIN {
  use Exporter ();
  use vars qw(@ISA @EXPORT);
  @ISA = qw(Exporter);
  @EXPORT = qw(prelude_start log_prelude_alert);
}

#Default:
my $prelude_client;

sub prelude_start {
  my($analyzer_name)=@_;
  my $version = `cd ../../..; build/get_version`;
  $prelude_client = new Prelude::ClientEasy($analyzer_name, 4, "SpamAssassin", "AntiSpam", "https://spamassassin.apache.org", $Mail::SpamAssassin::VERSION );
  $prelude_client->start();
}

sub log_prelude_alert {
  my($status, $tests, $scantime, $actual_length, $current_user, $uid, $msg_threshold, $mail)=@_;

  #Create an Idmef message
  my $idmef = new Prelude::IDMEF();

  #Get sender and recepient
  my ($to) = ($mail->get_pristine_header("To") =~ /<?(\S+?)>?$/);
  my ($from) = ($mail->get_pristine_header("From") =~ /<?(\S+?)>?$/);

  #Classification
  $idmef->set("alert.classification.text", "Spam found");

  $idmef->set("alert.assessment.impact.severity", "low");
  $idmef->set("alert.assessment.impact.completion", "failed");
  $idmef->set("alert.assessment.impact.type", "user");

  $idmef->set("alert.assessment.impact.description", untaint_var("SpamAssassin detected spam being sent to ".$current_user.".  This spam scored ".$status->get_score()." of a required $msg_threshold points."));

  #Source
  $idmef->set("alert.source(0).node.address(0).category", "e-mail");
  $idmef->set("alert.source(0).node.address(0).address", $from);

  #Target
  $idmef->set("alert.target(0).node.address(0).category", "e-mail");
  $idmef->set("alert.target(0).node.address(0).address", $to);
  $idmef->set("alert.target(0).user.user_id(0).type", "target-user");
  $idmef->set("alert.target(0).user.user_id(0).number", $uid);
  $idmef->set("alert.target(0).user.user_id(0).name", untaint_var($current_user));

  #Additional Data
  $idmef->set("alert.additional_data(>>).type", "string");
  $idmef->set("alert.additional_data(-1).meaning", "Signatures matched");
  $idmef->set("alert.additional_data(-1).data", $tests);

  $idmef->set("alert.additional_data(>>).type", "integer");
  $idmef->set("alert.additional_data(-1).meaning", "Score");
  $idmef->set("alert.additional_data(-1).data", $status->get_score());

  $idmef->set("alert.additional_data(>>).type", "string");
  $idmef->set("alert.additional_data(-1).meaning", "Required Score");
  $idmef->set("alert.additional_data(-1).data", $msg_threshold);

  $idmef->set("alert.additional_data(>>).type", "string");
  $idmef->set("alert.additional_data(-1).meaning", "Scan time");
  $idmef->set("alert.additional_data(-1).data", $scantime);

  $idmef->set("alert.additional_data(>>).type", "integer");
  $idmef->set("alert.additional_data(-1).meaning", "Size");
  $idmef->set("alert.additional_data(-1).data", $actual_length);

  #Send the generated message
  $prelude_client->sendIDMEF($idmef);

}
1;
