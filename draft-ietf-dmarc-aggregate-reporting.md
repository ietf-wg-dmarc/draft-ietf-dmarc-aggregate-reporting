%%%

	Title = "DMARC Aggregate Reporting"
	abbrev = "DMARC Aggregate Reporting"
	docName = "draft-ietf-dmarc-aggregate-reporting-00"
	category = "std"
	obsoletes = [7489]
	ipr = "trust200902"
	area = "Application"
	workgroup = "DMARC"
	submissiontype = "IETF"
	keyword = [""]
	
	date = "2021-01-04T00:00:00Z"
	
	[seriesInfo]
	name = "Internet-Draft"
	value = "draft-ietf-dmarc-aggregate-reporting-00"
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

This document (along with others) obsoletes RFC7489.

{mainmatter}

# Introduction

A key component of DMARC is the ability for domain holders to request that
receivers provide various types of reports.  These reports allow domain holders
to have insight into which IP addresses are sending on their behalf, and some
insight into whether or not the volume may be legitimate.  These reports expose
information relating to the DMARC policy, as well as the outcome of 
SPF [@!RFC7208] & DKIM [@!RFC6376] validation.


## Terminology

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when they appear in this document, are
 to be interpreted as described in [@RFC2119].

# DMARC Feedback

Providing Domain Owners with visibility into how Mail Receivers implement
and enforce the DMARC mechanism in the form of feedback is critical to
establishing and maintaining accurate authentication deployments.  When
Domain Owners can see what effect their policies and practices are having,
they are better willing and able to use quarantine and reject policies.

## Verifying External Destinations

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
authority component of a [URI] specified in the "rua" or "ruf" tag,
the following verification steps are to be taken:

1.  Extract the host portion of the authority component of the URI.
    Call this the "destination host", as it refers to a Report
    Receiver.

2.  Prepend the string "_report._dmarc".

3.  Prepend the domain name from which the policy was retrieved,
    after conversion to an A-label if needed.

4.  Query the DNS for a TXT record at the constructed name.  If the
    result of this request is a temporary DNS error of some kind
    (e.g., a timeout), the Mail Receiver MAY elect to temporarily
    fail the delivery so the verification test can be repeated later.

5.  For each record returned, parse the result as a series of
    "tag=value" pairs, i.e., the same overall format as the policy
    record (see Section 6.4).  In particular, the "v=DMARC1" tag is
    mandatory and MUST appear first in the list.  Discard any that do
    not pass this test.

6.  If the result includes no TXT resource records that pass basic
    parsing, a positive determination of the external reporting
    relationship cannot be made; stop.

7.  If at least one TXT resource record remains in the set after
    parsing, then the external reporting arrangement was authorized
    by the Report Receiver.

8.  If a "rua" or "ruf" tag is thus discovered, replace the
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

The format for these reports is defined in Appendix C.

The report SHOULD include the following data:

*  The DMARC policy discovered and applied, if any
*  The selected message disposition
*  The identifier evaluated by SPF and the SPF result, if any
*  The identifier evaluated by DKIM and the DKIM result, if any
*  For both DKIM and SPF, an indication of whether the identifier was
   in alignment
*  A separate report should be generated for each 5322.From subdomain, regardless
   of which policy domain was used during receipt of messages
*  Sending and receiving domains
*  The policy requested by the Domain Owner and the policy actually
   applied (if different)
*  The number of successful authentications
*  The counts of messages based on all messages received, even if
   their delivery is ultimately blocked by other filtering agents

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
*  generate a report whose end time occurs when the updated policy
   was detected, regardless of any requested report interval.

Such policy changes are expected to be infrequent for any given
domain, whereas more stringent policy monitoring requirements on the
Mail Receiver would produce a very large burden at Internet scale.
Therefore, it is the responsibility of report consumers and Domain
Owners to be aware of this situation and allow for such mixed reports
during the propagation of the new policy to Mail Receivers.

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

A Mail Receiver discovers reporting requests when it looks up a DMARC
policy record that corresponds to an RFC5322.From domain on received
mail.  The presence of the "rua" tag specifies where to send
feedback.


### Transport

   Where the URI specified in a "rua" tag does not specify otherwise, a
   Mail Receiver generating a feedback report SHOULD employ a secure
   transport mechanism.

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
   limits exceeded by the generated record), the Mail Receiver SHOULD
   send a short report (see Section 7.2.2) indicating that a report is
   available but could not be sent.  The Mail Receiver MAY cache that
   data and try again later, or MAY discard data that could not be sent.


#### Email

   The message generated by the Mail Receiver MUST be a [MAIL] message
   formatted per [MIME].  The aggregate report itself MUST be included
   in one of the parts of the message.  A human-readable portion MAY be
   included as a MIME part (such as a text/plain part).

   The aggregate data MUST be an XML file that SHOULD be subjected to
   GZIP compression.  Declining to apply compression can cause the
   report to be too large for a receiver to process (a commonly observed
   receiver limit is ten megabytes); doing the compression increases the
   chances of acceptance of the report at some compute cost.  The
   aggregate data SHOULD be present using the media type "application/
   gzip" if compressed (see [GZIP]), and "text/xml" otherwise.  The
   filename is typically constructed using the following ABNF:

     filename = receiver "!" policy-domain "!" begin-timestamp
                "!" end-timestamp [ "!" unique-id ] "." extension

     unique-id = 1*(ALPHA / DIGIT)

     receiver = domain
                ; imported from [MAIL]

     policy-domain   = domain

     begin-timestamp = 1*DIGIT
                       ; seconds since 00:00:00 UTC January 1, 1970
                       ; indicating start of the time range contained
                       ; in the report

     end-timestamp = 1*DIGIT
                     ; seconds since 00:00:00 UTC January 1, 1970
                     ; indicating end of the time range contained
                     ; in the report

     extension = "xml" / "xml.gz"

   The extension MUST be "xml" for a plain XML file, or "xml.gz" for an
   XML file compressed using GZIP.

   "unique-id" allows an optional unique ID generated by the Mail
   Receiver to distinguish among multiple reports generated
   simultaneously by different sources within the same Domain Owner.



   For example, this is a possible filename for the gzip file of a
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

   The RFC5322.Subject field for individual report submissions SHOULD
   conform to the following ABNF:

     dmarc-subject = %x52.65.70.6f.72.74 1*FWS       ; "Report"
                     %x44.6f.6d.61.69.6e.3a 1*FWS    ; "Domain:"
                     domain-name 1*FWS               ; from RFC 6376
                     %x53.75.62.6d.69.74.74.65.72.3a ; "Submitter:"
                     1*FWS domain-name 1*FWS
                     %x52.65.70.6f.72.74.2d.49.44.3a ; "Report-ID:"
                     msg-id                          ; from RFC 5322

   The first domain-name indicates the DNS domain name about which the
   report was generated.  The second domain-name indicates the DNS
   domain name representing the Mail Receiver generating the report.
   The purpose of the Report-ID: portion of the field is to enable the
   Domain Owner to identify and ignore duplicate reports that might be
   sent by a Mail Receiver.

   For instance, this is a possible Subject field for a report to the
   Domain Owner "example.com" from the Mail Receiver
   "mail.receiver.example".  It is line-wrapped as allowed by [MAIL]:

     Subject: Report Domain: example.com
         Submitter: mail.receiver.example
         Report-ID: <2002.02.15.1>

   This transport mechanism potentially encounters a problem when
   feedback data size exceeds maximum allowable attachment sizes for
   either the generator or the consumer.  See Section 7.2.2 for further
   discussion.


#### Other Methods

The specification as written allows for the addition of other
registered URI schemes to be supported in later versions.

# Extensible Reporting

A DMARC report should allow for some extensibility, as defined by
future documents that utilize DMARC as a foundation.  These extensions
MUST be properly formatted XML and meant to exist within the structure
of a DMARC report.  They MUST NOT alter the existing DMARC structure,
but instead exist self-contained within an `<extensions>` element. This
element MUST be a child of the `<feedback>` element.

```
<feedback>
  ...
  <extensions>
    <extension1 definition="https://path/to/spec">
      <data>...</data>
    </extension1>
  </extensions>
</feedback>
```

A DMARC report receiver SHOULD NOT generate a processing error when this
`<extensions>` element is absent or empty.  Furthermore, if a processor
is unable to handle an extension in a report, it SHOULD ignore the data,
and continue to the next extension.

# IANA Considerations

TBD

# Security Considerations

TBD

# Appendix A. DMARC XML Schema

<{{dmarc-xml-0.1.xsd}}

{backmatter}
