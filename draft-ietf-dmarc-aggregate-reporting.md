%%%

	Title = "DMARC Aggregate Reporting"
	abbrev = "DMARC Aggregate Reporting"
	docName = "draft-ietf-dmarc-aggregate-reporting-15"
	category = "std"
	obsoletes = [7489]
	ipr = "trust200902"
	area = "Application"
	workgroup = "DMARC"
	submissiontype = "IETF"
	keyword = [""]

	date = "2024-03-23T00:00:00Z"

	[seriesInfo]
	name = "Internet-Draft"
	value = "draft-ietf-dmarc-aggregate-reporting-15"
	stream = "IETF"
	status = "standard"

	[[author]]
	initials = "A."
	surname = "Brotman (ed)"
	fullname = "Alex Brotman"
	organization = "Comcast, Inc."
	  [author.address]
	  email = "alex_brotman@comcast.com"

%%%

.# Abstract

DMARC allows for domain holders to request aggregate reports from receivers.
This report is an XML document, and contains extensible elements that allow for 
other types of data to be specified later.  The aggregate reports can be
submitted to the domain holder's specified destination as supported by the
receiver.

This document (along with others) obsoletes [@!RFC7489].

{mainmatter}

# Introduction

A key component of DMARC [@!I-D.ietf-dmarc-dmarcbis] is the ability for domain holders to 
request that receivers provide various types of reports.  These reports allow 
domain holders to have insight into which IP addresses are sending on their 
behalf, and some insight into whether or not the volume may be legitimate.  
These reports expose information relating to the DMARC policy, as well as 
the outcome of SPF [@!RFC7208] & DKIM [@!RFC6376] validation.

## Terminology

In many IETF documents, several words, when they are in all capitals
as shown below, are used to signify the requirements in the
specification.  These capitalized words can bring significant clarity
and consistency to documents because their meanings are well defined.
This document defines how those words are interpreted in IETF
documents when the words are in all capitals.

*  These words can be used as defined here, but using them is not
   required.  Specifically, normative text does not require the use
   of these key words.  They are used for clarity and consistency
   when that is what's wanted, but a lot of normative text does not
   use them and is still normative.

*  The words have the meanings specified herein only when they are in
   all capitals.

*  When these words are not capitalized, they have their normal
   English meanings and are not affected by this document.

Authors who follow these guidelines should incorporate this phrase
near the beginning of their document:
```
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they
appear in all capitals, as shown here.
```

# DMARC Feedback

Providing Domain Owners with visibility into how Mail Receivers implement
and enforce the DMARC mechanism in the form of feedback is critical to
establishing and maintaining accurate authentication deployments.  When
Domain Owners can see what effect their policies and practices are having,
they are better willing and able to use quarantine and reject policies.


## Aggregate Reports

The DMARC aggregate feedback report is designed to provide Domain
Owners with precise insight into:

*  authentication results,
*  corrective action that needs to be taken by Domain Owners, and
*  the effect of Domain Owner DMARC policy on email streams processed
   by Mail Receivers.

Aggregate DMARC feedback provides visibility into real-world email
streams that Domain Owners need to make informed decisions regarding
the publication of DMARC policy.  When Domain Owners know what
legitimate mail they are sending, what the authentication results are
on that mail, and what forged mail receivers are getting, they can
make better decisions about the policies they need and the steps they
need to take to enable those policies.  When Domain Owners set
policies appropriately and understand their effects, Mail Receivers
can act on them confidently.

Visibility comes in the form of daily (or more frequent) Mail
Receiver-originated feedback reports that contain aggregate data on
message streams relevant to the Domain Owner.  This information
includes data about messages that passed DMARC authentication as well
as those that did not.

A separate report should be generated for each Policy Domain encountered 
during the reporting period. See below for further explanation in "Handling 
Domains in Reports".

The report may include the following data:

*  The DMARC policy discovered and applied, if any
*  The selected message disposition
*  The identifier evaluated by SPF and the SPF result, if any
*  The identifier evaluated by DKIM and the DKIM result, if any
*  For both DKIM and SPF, an indication of whether the identifier was
   in alignment
*  Sending and receiving domains
*  The number of successful authentications
*  The counts of messages based on all messages received, even if
   their delivery is ultimately blocked by other filtering agents.

The format for these reports is defined in Appendix A.

DMARC Aggregate Reports MUST contain two primary sections; one consisting
of descriptive information (with two elements), and the other a set of 
IP address-focused row-based data.  Each report MUST contain data for only one 
Policy Domain. A single report MUST contain data for one policy configuration. 
If multiple configurations were observed during a single reporting period, a 
reporting entity MAY choose to send multiple reports, otherwise the reporting 
entity SHOULD note only the final configuration observed during the 
period. See below for further information.

The informative section MUST contain two elements.  One will be the metadata 
section which MUST contain the fields related to `org_name`, `email`,
`report_id`, and `date_range`. Optional fields MAY include 
`extra_contact_info`, an `error` field.  The `date_range` field which will 
contain `begin` and `end` fields as epoch timestamps. The other element will 
be the `policy_published`, and record the policy configuration observed by 
the receiving system.  Mandatory fields are `domain`, `p`, `sp`. Optional 
fields are `fo`, `adkim`, `aspf`, `testing`, and `discovery_method`.  There 
MAY be an optional third section for `extensions`.

Within the data section, the report will contain row(s) of data stating which
IP addresses were seen to have delivered messages for the Author Domain to the receiving
system.  For each IP address that is being reported, there will be at least one `record` element,
which will then have each of a `row`, `identifiers`, and `auth_results` 
sub-element.  Within the `row` element, there MUST be `source_ip` and `count`.
There MUST also exist a `policy_evaluated`, with sub-elements of `disposition`,
`dkim`, and `spf`.  There MAY be an element for `reason`, meant to include 
any notes the reporter might want to include as to why the `disposition` policy
does not match the `policy_published`, such as a Local Policy override (See 
Section 2.1.5, Policy Override Reason).  The `dkim` and `spf` elements MUST be the 
evaluated values as they relate to DMARC, not the values the receiver may 
have used when overriding the policy.  Within the `identifiers` element, there 
MUST exist the data that was used to apply policy for the given IP address. 
There MUST be a `header_from` element, which will contain the RFC5322.From 
domain from the message.  There MAY be an optional `envelope_from` element, 
which contains the RFC5321.MailFrom domain or the RFC5321.Helo domain that 
the SPF check has been applied to. This element MAY be existing but empty 
if the message had a null reverse-path ([@!RFC5321], Section 4.5.5). There 
MAY be an optional `envelope_to` element, which contains the RFC5321.RcptTo 
domain from the message.

There MUST be an `auth_results` element within the `record` element.  This will
contain the data related to authenticating the messages associated with this sending
IP address. The `dkim` sub-element is optional as not all messages are signed, while there
MUST be at least one `spf` sub-element. These elements MUST have a `domain` that was
used during validation, as well as `result`. If validation is attempted for any DKIM
signature, the results MUST be included in the report (within reason, see "DKIM
Signatures in Aggregate Reports" below for handling numerous signatures).  The 
`dkim` element MUST include a `selector` element that was observed during 
validation. For the `spf` element, the `result` element MUST contain a 
lower-case string where the value is one of 
none/neutral/pass/fail/softfail/temperror/permerror (See [@?RFC8601]).  The `dkim` result
MUST contain a lower-case string where the value is one of 
none/pass/fail/policy/neutral/temperror/permerror. Both the `spf` and `dkim` results
may optionally include a `human_readable` field meant for the report to convey
more descriptive information back to the domain holder relating to evaluation
failures. There MAY exist an optional section for `extensions`.

### Handling Domains in Reports

In the same report, there MUST be a single Policy Domain, though there could be 
multiple RFC5322.From Domains.  Each RFC5322.From domain will create its own `record` 
within the report.  Consider the case where there are three domains with traffic 
volume to report: example.com, foo.example.com, and bar.example.com.  There will be 
explicit DMARC records for example.com and bar.example.com, with distinct policies.  There 
is no explicit DMARC record for foo.example.com, so it will be reliant on the 
policy described for example.com.  For a report period, there would now be two reports.  
The first will be for bar.example.com, and contain only one `record`, for 
bar.example.com.  The second report would be for example domain contain multiple 
`record` elements, one for example.com and one for foo.example.com (and extensibly, 
other `record` elements for subdomains which likewise did not have an explicit
DMARC policy declared).

### DKIM Signatures in Aggregate Reports

Within a single message, the possibility exists that there could be multiple DKIM
signatures. When validation of the message occurs, some signatures may pass,
while some may not.  As these pertain to DMARC, and especially to aggregate
reporting, reporters may not find it clear which DKIM signatures they should include
in a report. Signatures, regardless of outcome, could help the report ingester
determine the source of a message. However, there is a preference as to which
signatures are included.

1. A signature that passes DKIM, in strict alignment with the RFC5322.From domain
2. A signature that passes DKIM, in relaxed alignment with the RFC5322.From domain
3. Any other DKIM signatures that pass
4. DKIM signatures that do not pass

A report SHOULD contain no more than 100 signatures for a given `row`, in 
decreasing priority.

### Unique Identifiers in Aggregate Reporting

There are a few places where a unique identifier is specified as part of the
body of the report, the subject, and so on.  These unique identifiers should be
consistent per each report.  Specified below, the reader will see a 
`Report-ID` and `unique-id`.  These are the fields that MUST be identical when used.

### Error field

A few examples of information contained within the error field(s):

* DMARC DNS record evaluation errors (invalid rua or sp, etc.)
* Multiple DMARC records at a given location

Be mindful that the error field is an unbounded string, but should not contain
an extremely large body.  Provide enough information to assist the domain owner
with understanding some issues with their authentication or DMARC declaration.

### Policy Override Reason

The reason element, indicating an override of the DMARC policy, consists of a 
mandatory type field and an optional comment field. The type field MUST have 
one of the pre-defined values listed below. The comment field is an unbounded 
string for providing further details.

Possible values for the policy override type:

`forwarded`: The message was relayed via a known forwarder, or local
     heuristics identified the message as likely having been forwarded.
     There is no expectation that authentication would pass.

`local_policy`: The Mail Receiver's local policy exempted the message
     from being subjected to the Domain Owner's requested policy
     action.

`mailing_list`: Local heuristics determined that the message arrived
     via a mailing list, and thus authentication of the original
     message was not expected to succeed.

`other`: Some policy exception not covered by the other entries in
     this list occurred.  Additional detail can be found in the
     PolicyOverrideReason's "comment" field.

`sampled_out`: The message was exempted from application of policy by
     the testing mode ("t" tag) in the DMARC policy record.

`trusted_forwarder`: Message authentication failure was anticipated by
     other evidence linking the message to a locally maintained list of
     known and trusted forwarders.

## Extensions

There MAY be optional sections for extensions within the document.
The absence or existence of this section SHOULD NOT create an error when 
processing reports. This will be covered in a separate section.

## Changes in Policy During Reporting Period

Note that Domain Owners or their agents may change the published
DMARC policy for a domain or subdomain at any time.  From a Mail
Receiver's perspective, this will occur during a reporting period and
may be noticed during that period, at the end of that period when
reports are generated, or during a subsequent reporting period, all
depending on the Mail Receiver's implementation.  Under these
conditions, it is possible that a Mail Receiver could do any of the
following:

*  generate for such a reporting period a single aggregate report
   that includes message dispositions based on the old policy, or a
   mix of the two policies, even though the report only contains a
   single "policy_published" element;
*  generate multiple reports for the same period, one for each
   published policy occurring during the reporting period;

Such policy changes are expected to be infrequent for any given
domain, whereas more stringent policy monitoring requirements on the
Mail Receiver would produce a very large burden at Internet scale.
Therefore, it is the responsibility of report consumers and Domain
Owners to be aware of this situation and allow for such mixed reports
during the propagation of the new policy to Mail Receivers.

## Recommended Reporting Periods

Aggregate reports are most useful when they all cover a common time
period.  By contrast, correlation of these reports from multiple
generators when they cover incongruent time periods is difficult or
impossible.  Report generators SHOULD, wherever possible, adhere to
hour boundaries for the reporting period they are using.  For
example, starting a per-day report at 00:00; starting per-hour
reports at 00:00, 01:00, 02:00; etc.  Report generators using a
24-hour report period are strongly encouraged to begin that period at
00:00 UTC, regardless of local timezone or time of report production,
in order to facilitate correlation.

## Report Request Discovery

A Mail Receiver discovers reporting requests when it looks up a DMARC
policy record that corresponds to an RFC5322.From domain on received
mail.  The presence of the "rua" tag specifies where to send
feedback.


## Transport

The Mail Receiver, after preparing a report, MUST evaluate the
provided reporting URIs in the order given.  Any reporting URI that
includes a size limitation exceeded by the generated report (after
compression and after any encoding required by the particular
transport mechanism) MUST NOT be used.  An attempt MUST be made to
deliver an aggregate report to every remaining URI, up to the
Receiver's limits on supported URIs.

If transport is not possible because the services advertised by the
published URIs are not able to accept reports (e.g., the URI refers
to a service that is unreachable, or all provided URIs specify size
limits exceeded by the generated record), the Mail Receiver MAY 
send a short report indicating that a report is available but could 
not be sent.  The Mail Receiver MAY cache that data and try again 
later, or MAY discard data that could not be sent.

Where the URI specified in a "rua" tag does not specify otherwise, a
Mail Receiver generating a feedback report SHOULD employ a secure
transport mechanism.

### Definition of Report-ID

This identifier MUST be unique among reports to the same domain to 
aid receivers in identifying duplicate reports should they happen.

ridtxt = ("<" *(ALPHA / DIGIT / "." / "-") ["@" *(ALPHA / DIGIT / "." / "-")] ">") / (*(ALPHA / DIGIT / "." / "-") ["@" *(ALPHA / DIGIT / "." / "-")])

The format specified here is not very strict as the key goal is uniqueness.

### Email

The message generated by the Mail Receiver MUST be a [@!RFC5322] message
formatted per [@!RFC2045].  The aggregate report itself MUST be included
in one of the parts of the message.  A human-readable portion MAY be
included as a MIME part (such as a text/plain part).

The aggregate data MUST be an XML file that SHOULD be subjected to
GZIP compression.  Declining to apply compression can cause the
report to be too large for a receiver to process (the total message size
could exceed the receiver SMTP size limit); doing the compression increases 
the chances of acceptance of the report at some compute cost.  The
aggregate data MUST be present using the media type "application/
gzip" if compressed (see [@!RFC6713]), and "text/xml" otherwise.  The
filename MUST be constructed using the following ABNF:

  filename = receiver "!" policy-domain "!" begin-timestamp
             "!" end-timestamp [ "!" unique-id ] "." extension

  receiver = domain
             ; imported from [@!RFC5322]

  policy-domain   = domain

  begin-timestamp = 1*DIGIT
                    ; seconds since 00:00:00 UTC January 1, 1970
                    ; indicating start of the time range contained
                    ; in the report

  end-timestamp = 1*DIGIT
                  ; seconds since 00:00:00 UTC January 1, 1970
                  ; indicating end of the time range contained
                  ; in the report

  unique-id = 1*(ALPHA / DIGIT)

  extension = "xml" / "xml.gz"

The extension MUST be "xml" for a plain XML file, or "xml.gz" for an
XML file compressed using GZIP.

"unique-id" allows an optional unique ID generated by the Mail
Receiver to distinguish among multiple reports generated
simultaneously by different sources within the same Domain Owner.

If a report generator needs to re-send a report, the system MUST
use the same filename as the original report.  This would
allow the receiver to overwrite the data from the original, or discard
second instance of the report.

For example, this is a sample filename for the gzip file of a
report to the Domain Owner "example.com" from the Mail Receiver
"mail.receiver.example":

  mail.receiver.example!example.com!1013662812!1013749130.gz

No specific MIME message structure is required.  It is presumed that
the aggregate reporting address will be equipped to extract MIME
parts with the prescribed media type and filename and ignore the
rest.

Email streams carrying DMARC feedback data MUST conform to the DMARC
mechanism, thereby resulting in an aligned "pass" (see Section 3.1).
This practice minimizes the risk of report consumers processing
fraudulent reports.

The RFC5322.Subject field for individual report submissions MUST
conform to the following ABNF:

  dmarc-subject = %s"Report" 1*FWS %s"Domain:"
                  1*FWS domain-name 1*FWS         ; policy domain
                  %s"Submitter:" 1*FWS
                  domain-name 1*FWS               ; report generator
                  [ %s"Report-ID:" 1*FWS ridtxt ] ; defined below

The first domain-name indicates the DNS domain name about which the
report was generated.  The second domain-name indicates the DNS
domain name representing the Mail Receiver generating the report.
The purpose of the Report-ID: portion of the field is to enable the
Domain Owner to identify and ignore duplicate reports that might be
sent by a Mail Receiver.

For instance, this is a possible Subject field for a report to the
Domain Owner "example.com" from the Mail Receiver
"mail.receiver.example".  It is line-wrapped as allowed by [@!RFC5322]:

  Subject: Report Domain: example.com
      Submitter: mail.receiver.example
      Report-ID: <2002.02.15.1>

This transport mechanism potentially encounters a problem when
feedback data size exceeds maximum allowable attachment sizes for
either the generator or the consumer. 

Optionally, the report sender MAY choose to use the same `ridtxt`
as a part or whole of the RFC5322.Message-Id header included with the report.
Doing so may help receivers distinguish when a message is a re-transmission
or duplicate report.

### Other Methods

The specification as written allows for the addition of other
registered URI schemes to be supported in later versions.

### Handling of Duplicates

There may be a situation where the report generator attempts to deliver
duplicate information to the receiver.  This may manifest as an exact
duplicate of the report, or as duplicate information between two reports.
In these situations, the decision of how to handle the duplicate data
lies with the receiver.  As noted above, the sender MUST use the same
unique identifiers when sending the report.  This allows the receiver to
better understand when duplicates happen.  A few options on how to 
handle that duplicate information:

*  Reject back to sender, ideally with a permfail error noting
   the duplicate receipt
*  Discard upon receipt
*  Inspect the contents to evaluate the timestamps and reported data,
   act as appropriate
*  Accept the duplicate data

When accepting the data, that's likely in a situation where it's not
yet noticed, or a one-off experience.  Long term, duplicate data
is not ideal.  In the situation of a partial time frame overlap, there is
no clear way to distinguish the impact of the overlap.  The receiver would
need to accept or reject the duplicate data in whole.

# Verifying External Destinations

It is possible to specify destinations for the different reports that
are outside the authority of the Domain Owner making the request.
This allows domains that do not operate mail servers to request
reports and have them go someplace that is able to receive and
process them.

Without checks, this would allow a bad actor to publish a DMARC
policy record that requests that reports be sent to a victim address,
and then send a large volume of mail that will fail both DKIM and SPF
checks to a wide variety of destinations; the victim will in turn be
flooded with unwanted reports.  Therefore, a verification mechanism
is included.

When a Mail Receiver discovers a DMARC policy in the DNS, and the
Organizational Domain at which that record was discovered is not
identical to the Organizational Domain of the host part of the
authority component of a [@!RFC3986] specified in the "rua" tag,
the following verification steps MUST be taken:

1.  Extract the host portion of the authority component of the URI.
    Call this the "destination host", as it refers to a Report
    Receiver.

2.  Prepend the string "_report._dmarc".

3.  Prepend the domain name from which the policy was retrieved,
    after conversion to an A-label [@?RFC5890] if needed.

4.  Query the DNS for a TXT record at the constructed name.  If the
    result of this request is a temporary DNS error of some kind
    (e.g., a timeout), the Mail Receiver MAY elect to temporarily
    fail the delivery so the verification test can be repeated later.

5.  For each record returned, parse the result as a series of
    "tag=value" pairs, i.e., the same overall format as the policy
    record (see Section 5.4 in [@!I-D.ietf-dmarc-dmarcbis]).  In 
    particular, the "v=DMARC1" tag is mandatory and MUST appear 
    first in the list.  Discard any that do not pass this test.

6.  If the result includes no TXT resource records that pass basic
    parsing, a positive determination of the external reporting
    relationship cannot be made; stop.

7.  If at least one TXT resource record remains in the set after
    parsing, then the external reporting arrangement was authorized
    by the Report Receiver.

8.  If a "rua" tag is thus discovered, replace the
    corresponding value extracted from the domain's DMARC policy
    record with the one found in this record.  This permits the
    Report Receiver to override the report destination.  However, to
    prevent loops or indirect abuse, the overriding URI MUST use the
    same destination host from the first step.

For example, if a DMARC policy query for "blue.example.com" contained
"rua=mailto:reports@red.example.net", the host extracted from the
latter ("red.example.net") does not match "blue.example.com", so this
procedure is enacted.  A TXT query for
"blue.example.com._report._dmarc.red.example.net" is issued.  If a
single reply comes back containing a tag of "v=DMARC1", then the
relationship between the two is confirmed.  Moreover,
"red.example.net" has the opportunity to override the report
destination requested by "blue.example.com" if needed.

Where the above algorithm fails to confirm that the external
reporting was authorized by the Report Receiver, the URI MUST be
ignored by the Mail Receiver generating the report.  Further, if the
confirming record includes a URI whose host is again different than
the domain publishing that override, the Mail Receiver generating the
report MUST NOT generate a report to either the original or the
override URI.
A Report Receiver publishes such a record in its DNS if it wishes to
receive reports for other domains.

A Report Receiver that is willing to receive reports for any domain
can use a wildcard DNS record.  For example, a TXT resource record at
"*._report._dmarc.example.com" containing at least "v=DMARC1"
confirms that example.com is willing to receive DMARC reports for any
domain.

If the Report Receiver is overcome by volume, it can simply remove
the confirming DNS record.  However, due to positive caching, the
change could take as long as the time-to-live (TTL) on the record to
go into effect.

A Mail Receiver might decide not to enact this procedure if, for
example, it relies on a local list of domains for which external
reporting addresses are permitted.

# Extensible Reporting

DMARC reports allow for some extensibility, as defined by future
documents that utilize DMARC as a foundation.  These extensions
MUST be properly formatted XML and meant to exist within the structure
of a DMARC report.  Two positions of type `<any>` are provided in the
existing DMARC structure, one at file level, in an `<extension>` element
after `<policy_published>` and one at record level, after `<auth_results>`.
In either case, the extensions MUST contain a URI to the definition of
the extension so that the receiver understands how to interpret the data.

At file level:
```xml
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0"
          xmlns:ext="URI for an extension-supplied name space">
  ...
  <policy_published>
    <domain>example.com</domain>
    <p>quarantine</p>
    <sp>none</sp>
    <testing>n</testing>
  </policy_published>
  <extension>
    <ext:arc-override>never</ext:arc-override>
  </extension>
```

Within the `record` element:
```xml
  <record>
    <row>
       ...
    </row>
    <identifiers>
       ...
    </identifiers>
    <auth_results>
       ...
    </auth_results>
    <ext:arc-results>
       ...
    </ext:arc-results>
  </record>
  <record>
     ...
```

Here "arc-override" and "arc-results" are hypothetical element names
defined in the extension's name space.

Extension elements are optional.  Any number of extensions is allowed.
If a processor is unable to handle an extension in a report, it SHOULD
ignore the data and continue to the next extension.


# IANA Considerations

This document uses URNs to describe XML namespaces and XML schemas
conforming to a registry mechanism described in [@!RFC3688].  Two URI
assignments will be registered by the IANA.

## Registration request for the DMARC namespace:

URI: urn:ietf:params:xml:ns:dmarc-2.0

Registrant Contact: See the "Author's Address" section of this document.

XML: None.  Namespace URIs do not represent an XML specification.

## Registration request for the DMARC XML schema:

URI: urn:ietf:params:xml:schema:dmarc-2.0

Registrant Contact: See the "Author's Address" section of this document.

XML: See Appendix A. DMARC XML Schema in this document.


# Privacy Considerations

This section will discuss exposure related to DMARC aggregate reporting.

## Report Recipients

A DMARC record can specify that reports should be sent to an
intermediary operating on behalf of the Domain Owner.  This is done
when the Domain Owner contracts with an entity to monitor mail
streams for abuse and performance issues.  Receipt by third parties
of such data may or may not be permitted by the Mail Receiver's
privacy policy, terms of use, or other similar governing document.
Domain Owners and Mail Receivers should both review and understand if
their own internal policies constrain the use and transmission of
DMARC reporting.

Some potential exists for report recipients to perform traffic
analysis, making it possible to obtain metadata about the Receiver's
traffic.  In addition to verifying compliance with policies,
Receivers need to consider that before sending reports to a third
party.

## Data Contained Within Reports

Aggregate feedback reports contain aggregated data relating to 
messages purportedly originating from the Domain Owner. The data 
does not contain any identifying characteristics about individual 
users. No personal information such as individual email addresses, 
IP addresses of individuals, or the content of any messages, is 
included in reports.

Mail Receivers should have no concerns in sending reports as they 
do not contain personal information. In all cases, the data within 
the reports relates to the domain-level authentication information 
provided by mail servers sending messages on behalf of the Domain 
Owner. This information is necessary to assist Domain Owners in 
implementing and maintaining DMARC.

Domain Owners should have no concerns in receiving reports as 
they do not contain personal information. The reports only contain 
aggregated data related to the domain-level authentication details 
of messages claiming to originate from their domain. This information 
is essential for the proper implementation and operation of DMARC. 
Domain Owners who are unable to receive reports for organizational 
reasons, can choose to exclusively direct the reports to an 
external processor.  

## Feedback Leakage {#leakage}

Providing feedback reporting to PSOs for a PSD [@?RFC9091] can, in 
some cases, cause information to leak out of an organization to 
the PSO.  This leakage could potentially be utilized as part of a 
program of pervasive surveillance (see [@!RFC7624]]).  There are 
roughly three cases to consider:

Single Organization PSDs (e.g., ".mil"):
:  RUA reports based on PSD DMARC have the potential to
   contain information about emails related to entities managed by
   the organization.  Since both the PSO and the Organizational
   Domain Owners are common, there is no additional privacy risk for
   either normal or non-existent domain reporting due to PSD DMARC.

Multi-organization PSDs that require DMARC usage (e.g., ".bank"):
:  Reports based on PSD DMARC will only be generated for domains that
   do not publish a DMARC policy at the organizational or host level.
   For domains that do publish the required DMARC policy records, the
   feedback reporting addresses of the organization (or
   hosts) will be used.  The only direct risk of feedback leakage for
   these PSDs are for Organizational Domains that are out of
   compliance with PSD policy.  Data on non-existent cousin domains
   would be sent to the PSO.

Multi-organization PSDs (e.g., ".com") that do not mandate DMARC
usage:
:  Privacy risks for Organizational Domains that have not deployed
   DMARC within such PSDs are significant.  For non-DMARC
   Organizational Domains, all DMARC feedback will be directed to the
   PSO.  Any non-DMARC Organizational Domain would have its Feedback
   Reports redirected to the PSO.  The content of such reports,
   particularly for existing domains, is privacy sensitive.

PSOs will receive feedback on non-existent domains, which may be
similar to existing Organizational Domains.  Feedback related to such
cousin domains have a small risk of carrying information related to
an actual Organizational Domain.  To minimize this potential concern,
PSD DMARC feedback MUST be limited to Aggregate Reports.  Feedback
Reports carry more detailed information and present a greater risk.

Due to the inherent privacy and security risks associated with DMARC at the
PSD level for Organizational Domains in multi-organization PSDs that do
not participate in DMARC, any feedback reporting related to multi-
organizational PSDs MUST be limited to non-existent domains except in
cases where the reporter knows that PSO requires use of DMARC.

# Security Considerations

* Aggregate reports are supposed to be processed automatically. An attacker might attempt to compromise the integrity or availability of the report processor by sending ill-formed reports. In particular, the archive decompressor and XML parser are at risk to resource exhaustion attacks (zip bomb or XML bomb).
* The data contained within aggregate reports may be forged. An attacker might attempt to interfere by submitting false reports in masses.
* See also the security considerations of [dmarc-bis] (Section 11).

# Appendix A. DMARC XML Schema

<{{dmarc-xml-0.2.xsd}}

# Appendix B. Sample Report

<{{dmarc-xml-0.2.xml}}

# Acknowledgements

TBD

{backmatter}
