# This is taken from the JSON::PP package and included in the Nikto source.
# It has been modified slightly.
package # This is JSON::backportPP
JSON::PP;
use 5.005;
use base qw(Exporter);
use overload ();
use B ();
$JSON::PP::VERSION = '2.27200';
@JSON::PP::EXPORT = qw(encode_json decode_json from_json to_json);
use constant P_ASCII                => 0;
use constant P_LATIN1               => 1;
use constant P_UTF8                 => 2;
use constant P_INDENT               => 3;
use constant P_CANONICAL            => 4;
use constant P_SPACE_BEFORE         => 5;
use constant P_SPACE_AFTER          => 6;
use constant P_ALLOW_NONREF         => 7;
use constant P_SHRINK               => 8;
use constant P_ALLOW_BLESSED        => 9;
use constant P_CONVERT_BLESSED      => 10;
use constant P_RELAXED              => 11;
use constant P_LOOSE                => 12;
use constant P_ALLOW_BIGNUM         => 13;
use constant P_ALLOW_BAREKEY        => 14;
use constant P_ALLOW_SINGLEQUOTE    => 15;
use constant P_ESCAPE_SLASH         => 16;
use constant P_AS_NONBLESSED        => 17;
use constant P_ALLOW_UNKNOWN        => 18;
use constant OLD_PERL => $] < 5.008 ? 1 : 0;
BEGIN {
my @xs_compati_bit_properties = qw(
latin1 ascii utf8 indent canonical space_before space_after allow_nonref shrink
allow_blessed convert_blessed relaxed allow_unknown
);
my @pp_bit_properties = qw(
allow_singlequote allow_bignum loose
allow_barekey escape_slash as_nonblessed
);
if ($] < 5.008 ) {
my $helper = $] >= 5.006 ? 'JSON::backportPP::Compat5006' : 'JSON::backportPP::Compat5005';
eval qq| require $helper |;
if ($@) { print "JSON ERROR: $@\n"; }
}
for my $name (@xs_compati_bit_properties, @pp_bit_properties) {
my $flag_name = 'P_' . uc($name);
eval qq/
            sub $name {
                my \$enable = defined \$_[1] ? \$_[1] : 1;

                if (\$enable) {
                    \$_[0]->{PROPS}->[$flag_name] = 1;
                }
                else {
                    \$_[0]->{PROPS}->[$flag_name] = 0;
                }

                \$_[0];
            }
            sub get_$name {
                \$_[0]->{PROPS}->[$flag_name] ? 1 : '';
            }
        /;
}
}
my %encode_allow_method = map {($_ => 1)} qw/utf8 pretty allow_nonref latin1 self_encode escape_slash allow_blessed convert_blessed indent indent_length allow_bignum as_nonblessed/;
my %decode_allow_method= map {($_ => 1)} qw/utf8 allow_nonref loose allow_singlequote allow_bignum allow_barekey max_size relaxed/;
my $JSON;
sub encode_json ($) {
($JSON ||= __PACKAGE__->new->utf8)->encode(@_);
}
sub decode_json {
($JSON ||= __PACKAGE__->new->utf8)->decode(@_);
}
sub new {
my $class = shift;
my $self  = {
max_depth   => 512,
max_size    => 0,
indent      => 0,
FLAGS       => 0,
fallback      => sub { encode_error('Invalid value. JSON can only reference.') },
indent_length => 3,
};
bless $self, $class;
}
sub encode {
return $_[0]->PP_encode_json($_[1]);
}
sub decode {
return $_[0]->PP_decode_json($_[1], 0x00000000);
}
sub decode_prefix {
return $_[0]->PP_decode_json($_[1], 0x00000001);
}
sub pretty {
my ($self, $v) = @_;
my $enable = defined $v ? $v : 1;
if ($enable) {
$self->indent(1)->indent_length(3)->space_before(1)->space_after(1);
}
else {
$self->indent(0)->space_before(0)->space_after(0);
}
$self;
}
sub max_depth {
my $max  = defined $_[1] ? $_[1] : 0x80000000;
$_[0]->{max_depth} = $max;
$_[0];
}
sub get_max_depth { $_[0]->{max_depth}; }
sub max_size {
my $max  = defined $_[1] ? $_[1] : 0;
$_[0]->{max_size} = $max;
$_[0];
}
sub get_max_size { $_[0]->{max_size}; }
sub filter_json_object {
$_[0]->{cb_object} = defined $_[1] ? $_[1] : 0;
$_[0]->{F_HOOK} = ($_[0]->{cb_object} or $_[0]->{cb_sk_object}) ? 1 : 0;
$_[0];
}
sub filter_json_single_key_object {
if (@_ > 1) {
$_[0]->{cb_sk_object}->{$_[1]} = $_[2];
}
$_[0]->{F_HOOK} = ($_[0]->{cb_object} or $_[0]->{cb_sk_object}) ? 1 : 0;
$_[0];
}
sub indent_length {
if (!defined $_[1] or $_[1] > 15 or $_[1] < 0) {
print "The acceptable range of indent_length() is 0 to 15.";
}
else {
$_[0]->{indent_length} = $_[1];
}
$_[0];
}
sub get_indent_length {
$_[0]->{indent_length};
}
sub sort_by {
$_[0]->{sort_by} = defined $_[1] ? $_[1] : 1;
$_[0];
}
{ 
my $max_depth;
my $indent;
my $ascii;
my $latin1;
my $utf8;
my $space_before;
my $space_after;
my $canonical;
my $allow_blessed;
my $convert_blessed;
my $indent_length;
my $escape_slash;
my $bignum;
my $as_nonblessed;
my $depth;
my $indent_count;
my $keysort;
sub PP_encode_json {
my $self = shift;
my $obj  = shift;
$indent_count = 0;
$depth        = 0;
my $idx = $self->{PROPS};
($ascii, $latin1, $utf8, $indent, $canonical, $space_before, $space_after, $allow_blessed,
$convert_blessed, $escape_slash, $bignum, $as_nonblessed)= @{$idx}[P_ASCII .. P_SPACE_AFTER, P_ALLOW_BLESSED, P_CONVERT_BLESSED,
P_ESCAPE_SLASH, P_ALLOW_BIGNUM, P_AS_NONBLESSED];
($max_depth, $indent_length) = @{$self}{qw/max_depth indent_length/};
$keysort = $canonical ? sub { $a cmp $b } : undef;
if ($self->{sort_by}) {
$keysort = ref($self->{sort_by}) eq 'CODE' ? $self->{sort_by}
: $self->{sort_by} =~ /\D+/       ? $self->{sort_by}
: sub { $a cmp $b };
}
encode_error("hash- or arrayref expected (not a simple scalar, use allow_nonref to allow this)")
if(!ref $obj and !$idx->[ P_ALLOW_NONREF ]);
my $str  = $self->object_to_json($obj);
$str .= "\n" if ( $indent );
unless ($ascii or $latin1 or $utf8) {
utf8::upgrade($str);
}
if ($idx->[ P_SHRINK ]) {
utf8::downgrade($str, 1);
}
return $str;
}
sub object_to_json {
my ($self, $obj) = @_;
my $type = ref($obj);
if($type eq 'HASH'){
return $self->hash_to_json($obj);
}
elsif($type eq 'ARRAY'){
return $self->array_to_json($obj);
}
elsif ($type) {
if (blessed($obj)) {
return $self->value_to_json($obj) if ( $obj->isa('JSON::PP::Boolean') );
if ( $convert_blessed and $obj->can('TO_JSON') ) {
my $result = $obj->TO_JSON();
if ( defined $result and ref( $result ) ) {
if ( refaddr( $obj ) eq refaddr( $result ) ) {
encode_error( sprintf(
"%s::TO_JSON method returned same object as was passed instead of a new one",
ref $obj
) );
}
}
return $self->object_to_json( $result );
}
return "$obj" if ( $bignum and _is_bignum($obj) );
return $self->blessed_to_json($obj) if ($allow_blessed and $as_nonblessed);
encode_error( sprintf("encountered object '%s', but neither allow_blessed "
. "nor convert_blessed settings are enabled", $obj)
) unless ($allow_blessed);
return 'null';
}
else {
return $self->value_to_json($obj);
}
}
else{
return $self->value_to_json($obj);
}
}
sub hash_to_json {
my ($self, $obj) = @_;
my @res;
encode_error("json text or perl structure exceeds maximum nesting level (max_depth set too low?)")
if (++$depth > $max_depth);
my ($pre, $post) = $indent ? $self->_up_indent() : ('', '');
my $del = ($space_before ? ' ' : '') . ':' . ($space_after ? ' ' : '');
for my $k ( _sort( $obj ) ) {
if ( OLD_PERL ) { utf8::decode($k) }
push @res, string_to_json( $self, $k )
.  $del
. ( $self->object_to_json( $obj->{$k} ) || $self->value_to_json( $obj->{$k} ) );
}
 --$depth;
$self->_down_indent() if ($indent);
return   '{' . ( @res ? $pre : '' ) . ( @res ? join( ",$pre", @res ) . $post : '' )  . '}';
}
sub array_to_json {
my ($self, $obj) = @_;
my @res;
encode_error("json text or perl structure exceeds maximum nesting level (max_depth set too low?)")
if (++$depth > $max_depth);
my ($pre, $post) = $indent ? $self->_up_indent() : ('', '');
for my $v (@$obj){
push @res, $self->object_to_json($v) || $self->value_to_json($v);
}
--$depth;
$self->_down_indent() if ($indent);
return '[' . ( @res ? $pre : '' ) . ( @res ? join( ",$pre", @res ) . $post : '' ) . ']';
}
sub value_to_json {
my ($self, $value) = @_;
return 'null' if(!defined $value);
my $b_obj = B::svref_2object(\$value);
my $flags = $b_obj->FLAGS;
return $value
if $flags & ( B::SVp_IOK | B::SVp_NOK ) and !( $flags & B::SVp_POK );
my $type = ref($value);
if(!$type){
return string_to_json($self, $value);
}
elsif( blessed($value) and  $value->isa('JSON::PP::Boolean') ){
return $$value == 1 ? 'true' : 'false';
}
elsif ($type) {
if ((overload::StrVal($value) =~ /=(\w+)/)[0]) {
return $self->value_to_json("$value");
}
if ($type eq 'SCALAR' and defined $$value) {
return   $$value eq '1' ? 'true'
: $$value eq '0' ? 'false'
: $self->{PROPS}->[ P_ALLOW_UNKNOWN ] ? 'null'
: encode_error("cannot encode reference to scalar");
}
if ( $self->{PROPS}->[ P_ALLOW_UNKNOWN ] ) {
return 'null';
}
else {
if ( $type eq 'SCALAR' or $type eq 'REF' ) {
encode_error("cannot encode reference to scalar");
}
else {
encode_error("encountered $value, but JSON can only represent references to arrays or hashes");
}
}
}
else {
return $self->{fallback}->($value)
if ($self->{fallback} and ref($self->{fallback}) eq 'CODE');
return 'null';
}
}
my %esc = (
"\n" => '\n',
"\r" => '\r',
"\t" => '\t',
"\f" => '\f',
"\b" => '\b',
"\"" => '\"',
"\\" => '\\\\',
"\'" => '\\\'',
);
sub string_to_json {
my ($self, $arg) = @_;
$arg =~ s/([\x22\x5c\n\r\t\f\b])/$esc{$1}/g;
$arg =~ s/\//\\\//g if ($escape_slash);
$arg =~ s/([\x00-\x08\x0b\x0e-\x1f])/'\\u00' . unpack('H2', $1)/eg;
if ($ascii) {
$arg = JSON_PP_encode_ascii($arg);
}
if ($latin1) {
$arg = JSON_PP_encode_latin1($arg);
}
if ($utf8) {
utf8::encode($arg);
}
return '"' . $arg . '"';
}
sub blessed_to_json {
my $reftype = reftype($_[1]) || '';
if ($reftype eq 'HASH') {
return $_[0]->hash_to_json($_[1]);
}
elsif ($reftype eq 'ARRAY') {
return $_[0]->array_to_json($_[1]);
}
else {
return 'null';
}
}
sub encode_error {
my $error  = shift;
print "JSON ERROR: $error";
}
sub _sort {
defined $keysort ? (sort $keysort (keys %{$_[0]})) : keys %{$_[0]};
}
sub _up_indent {
my $self  = shift;
my $space = ' ' x $indent_length;
my ($pre,$post) = ('','');
$post = "\n" . $space x $indent_count;
$indent_count++;
$pre = "\n" . $space x $indent_count;
return ($pre,$post);
}
sub _down_indent { $indent_count--; }
sub PP_encode_box {
{
depth        => $depth,
indent_count => $indent_count,
};
}
} 
sub _encode_ascii {
join('',
map {
$_ <= 127 ?
chr($_) :
$_ <= 65535 ?
sprintf('\u%04x', $_) : sprintf('\u%x\u%x', _encode_surrogates($_));
} unpack('U*', $_[0])
);
}
sub _encode_latin1 {
join('',
map {
$_ <= 255 ?
chr($_) :
$_ <= 65535 ?
sprintf('\u%04x', $_) : sprintf('\u%x\u%x', _encode_surrogates($_));
} unpack('U*', $_[0])
);
}
sub _encode_surrogates {
my $uni = $_[0] - 0x10000;
return ($uni / 0x400 + 0xD800, $uni % 0x400 + 0xDC00);
}
sub _is_bignum {
$_[0]->isa('Math::BigInt') or $_[0]->isa('Math::BigFloat');
}
my $max_intsize;
BEGIN {
my $checkint = 1111;
for my $d (5..64) {
$checkint .= 1;
my $int   = eval qq| $checkint |;
if ($int =~ /[eE]/) {
$max_intsize = $d - 1;
last;
}
}
}
{   my %escapes = (
b    => "\x8",
t    => "\x9",
n    => "\xA",
f    => "\xC",
r    => "\xD",
'\\' => '\\',
'"'  => '"',
'/'  => '/',
);
my $text;
my $at;
my $ch;
my $len;
my $depth;
my $encoding;
my $is_valid_utf8;
my $utf8_len;
	my $utf8;
my $max_depth;
my $max_size;
my $relaxed;
my $cb_object;
my $cb_sk_object;
my $F_HOOK;
my $allow_bigint;
my $singlequote;
my $loose;
my $allow_barekey;
sub PP_decode_json {
my ($self, $opt);
($self, $text, $opt) = @_;
($at, $ch, $depth) = (0, '', 0);
if ( !defined $text or ref $text ) {
decode_error("malformed JSON string, neither array, object, number, string or atom");
}
my $idx = $self->{PROPS};
($utf8, $relaxed, $loose, $allow_bigint, $allow_barekey, $singlequote) = @{$idx}[P_UTF8, P_RELAXED, P_LOOSE .. P_ALLOW_SINGLEQUOTE];
if ( $utf8 ) {
utf8::downgrade( $text, 1 ) or print "JSON ERROR: Wide character in subroutine entry";
}
else {
utf8::upgrade( $text );
}
$len = length $text;
($max_depth, $max_size, $cb_object, $cb_sk_object, $F_HOOK) = @{$self}{qw/max_depth  max_size cb_object cb_sk_object F_HOOK/};
if ($max_size > 1) {
use bytes;
my $bytes = length $text;
decode_error(
sprintf("attempted decode of JSON text of %s bytes size, but max_size is set to %s"
, $bytes, $max_size), 1
) if ($bytes > $max_size);
}
my @octets = unpack('C4', $text);
$encoding =   ( $octets[0] and  $octets[1]) ? 'UTF-8'
: (!$octets[0] and  $octets[1]) ? 'UTF-16BE'
: (!$octets[0] and !$octets[1]) ? 'UTF-32BE'
: ( $octets[2]                ) ? 'UTF-16LE'
: (!$octets[2]                ) ? 'UTF-32LE'
: 'unknown';
white();
my $valid_start = defined $ch;
my $result = value();
return undef if ( !$result && ( $opt & 0x10000000 ) );
decode_error("malformed JSON string, neither array, object, number, string or atom") unless $valid_start;
if ( !$idx->[ P_ALLOW_NONREF ] and !ref $result ) {
decode_error(
'JSON text must be an object or array (but found number, string, true, false or null,'
. ' use allow_nonref to allow this)', 1);
}
print "JSON ERROR: something wrong." if $len < $at;
my $consumed = defined $ch ? $at - 1 : $at;
white();
if ( $ch ) {
return ( $result, $consumed ) if ($opt & 0x00000001);
decode_error("garbage after JSON object");
}
( $opt & 0x00000001 ) ? ( $result, $consumed ) : $result;
}
sub next_chr {
return $ch = undef if($at >= $len);
$ch = substr($text, $at++, 1);
}
sub value {
white();
return          if(!defined $ch);
return object() if($ch eq '{');
return array()  if($ch eq '[');
return string() if($ch eq '"' or ($singlequote and $ch eq "'"));
return number() if($ch =~ /[0-9]/ or $ch eq '-');
return word();
}
sub string {
my ($i, $s, $t, $u);
my $utf16;
my $is_utf8;
($is_valid_utf8, $utf8_len) = ('', 0);
$s = '';
if($ch eq '"' or ($singlequote and $ch eq "'")){
my $boundChar = $ch;
OUTER: while( defined(next_chr()) ){
if($ch eq $boundChar){
next_chr();
if ($utf16) {
decode_error("missing low surrogate character in surrogate pair");
}
utf8::decode($s) if($is_utf8);
return $s;
}
elsif($ch eq '\\'){
next_chr();
if(exists $escapes{$ch}){
$s .= $escapes{$ch};
}
elsif($ch eq 'u'){
my $u = '';
for(1..4){
$ch = next_chr();
last OUTER if($ch !~ /[0-9a-fA-F]/);
$u .= $ch;
}
if ($u =~ /^[dD][89abAB][0-9a-fA-F]{2}/) {
$utf16 = $u;
}
elsif ($u =~ /^[dD][c-fC-F][0-9a-fA-F]{2}/) {
unless (defined $utf16) {
decode_error("missing high surrogate character in surrogate pair");
}
$is_utf8 = 1;
$s .= JSON_PP_decode_surrogates($utf16, $u) || next;
$utf16 = undef;
}
else {
if (defined $utf16) {
decode_error("surrogate pair expected");
}
if ( ( my $hex = hex( $u ) ) > 127 ) {
$is_utf8 = 1;
$s .= JSON_PP_decode_unicode($u) || next;
}
else {
$s .= chr $hex;
}
}
}
else{
unless ($loose) {
$at -= 2;
decode_error('illegal backslash escape sequence in string');
}
$s .= $ch;
}
}
else{
if ( ord $ch  > 127 ) {
if ( $utf8 ) {
unless( $ch = is_valid_utf8($ch) ) {
$at -= 1;
decode_error("malformed UTF-8 character in JSON string");
}
else {
$at += $utf8_len - 1;
}
}
else {
utf8::encode( $ch );
}
$is_utf8 = 1;
}
if (!$loose) {
if ($ch =~ /[\x00-\x1f\x22\x5c]/)  {
$at--;
decode_error('invalid character encountered while parsing JSON string');
}
}
$s .= $ch;
}
}
}
decode_error("unexpected end of string while parsing JSON string");
}
sub white {
while( defined $ch  ){
if($ch le ' '){
next_chr();
}
elsif($ch eq '/'){
next_chr();
if(defined $ch and $ch eq '/'){
1 while(defined(next_chr()) and $ch ne "\n" and $ch ne "\r");
}
elsif(defined $ch and $ch eq '*'){
next_chr();
while(1){
if(defined $ch){
if($ch eq '*'){
if(defined(next_chr()) and $ch eq '/'){
next_chr();
last;
}
}
else{
next_chr();
}
}
else{
decode_error("Unterminated comment");
}
}
next;
}
else{
$at--;
decode_error("malformed JSON string, neither array, object, number, string or atom");
}
}
else{
if ($relaxed and $ch eq '#') {
pos($text) = $at;
$text =~ /\G([^\n]*(?:\r\n|\r|\n|$))/g;
$at = pos($text);
next_chr;
next;
}
last;
}
}
}
sub array {
my $a  = $_[0] || [];
decode_error('json text or perl structure exceeds maximum nesting level (max_depth set too low?)')
if (++$depth > $max_depth);
next_chr();
white();
if(defined $ch and $ch eq ']'){
--$depth;
next_chr();
return $a;
}
else {
while(defined($ch)){
push @$a, value();
white();
if (!defined $ch) {
last;
}
if($ch eq ']'){
--$depth;
next_chr();
return $a;
}
if($ch ne ','){
last;
}
next_chr();
white();
if ($relaxed and $ch eq ']') {
--$depth;
next_chr();
return $a;
}
}
}
decode_error(", or ] expected while parsing array");
}
sub object {
my $o = $_[0] || {};
my $k;
decode_error('json text or perl structure exceeds maximum nesting level (max_depth set too low?)')
if (++$depth > $max_depth);
next_chr();
white();
if(defined $ch and $ch eq '}'){
--$depth;
next_chr();
if ($F_HOOK) {
return _json_object_hook($o);
}
return $o;
}
else {
while (defined $ch) {
$k = ($allow_barekey and $ch ne '"' and $ch ne "'") ? bareKey() : string();
white();
if(!defined $ch or $ch ne ':'){
$at--;
decode_error("':' expected");
}
next_chr();
$o->{$k} = value();
white();
last if (!defined $ch);
if($ch eq '}'){
--$depth;
next_chr();
if ($F_HOOK) {
return _json_object_hook($o);
}
return $o;
}
if($ch ne ','){
last;
}
next_chr();
white();
if ($relaxed and $ch eq '}') {
--$depth;
next_chr();
if ($F_HOOK) {
return _json_object_hook($o);
}
return $o;
}
}
}
$at--;
decode_error(", or } expected while parsing object/hash");
}
sub bareKey {
my $key;
while($ch =~ /[^\x00-\x23\x25-\x2F\x3A-\x40\x5B-\x5E\x60\x7B-\x7F]/){
$key .= $ch;
next_chr();
}
return $key;
}
sub word {
my $word =  substr($text,$at-1,4);
if($word eq 'true'){
$at += 3;
next_chr;
return $JSON::PP::true;
}
elsif($word eq 'null'){
$at += 3;
next_chr;
return undef;
}
elsif($word eq 'fals'){
$at += 3;
if(substr($text,$at,1) eq 'e'){
$at++;
next_chr;
return $JSON::PP::false;
}
}
$at--;
decode_error("'null' expected")  if ($word =~ /^n/);
decode_error("'true' expected")  if ($word =~ /^t/);
decode_error("'false' expected") if ($word =~ /^f/);
decode_error("malformed JSON string, neither array, object, number, string or atom");
}
sub number {
my $n    = '';
my $v;
if($ch eq '0'){
my $peek = substr($text,$at,1);
my $hex  = $peek =~ /[xX]/;
if($hex){
decode_error("malformed number (leading zero must not be followed by another digit)");
($n) = ( substr($text, $at+1) =~ /^([0-9a-fA-F]+)/);
}
else{
($n) = ( substr($text, $at) =~ /^([0-7]+)/);
if (defined $n and length $n > 1) {
decode_error("malformed number (leading zero must not be followed by another digit)");
}
}
if(defined $n and length($n)){
if (!$hex and length($n) == 1) {
decode_error("malformed number (leading zero must not be followed by another digit)");
}
$at += length($n) + $hex;
next_chr;
return $hex ? hex($n) : oct($n);
}
}
if($ch eq '-'){
$n = '-';
next_chr;
if (!defined $ch or $ch !~ /\d/) {
decode_error("malformed number (no digits after initial minus)");
}
}
while(defined $ch and $ch =~ /\d/){
$n .= $ch;
next_chr;
}
if(defined $ch and $ch eq '.'){
$n .= '.';
next_chr;
if (!defined $ch or $ch !~ /\d/) {
decode_error("malformed number (no digits after decimal point)");
}
else {
$n .= $ch;
}
while(defined(next_chr) and $ch =~ /\d/){
$n .= $ch;
}
}
if(defined $ch and ($ch eq 'e' or $ch eq 'E')){
$n .= $ch;
next_chr;
if(defined($ch) and ($ch eq '+' or $ch eq '-')){
$n .= $ch;
next_chr;
if (!defined $ch or $ch =~ /\D/) {
decode_error("malformed number (no digits after exp sign)");
}
$n .= $ch;
}
elsif(defined($ch) and $ch =~ /\d/){
$n .= $ch;
}
else {
decode_error("malformed number (no digits after exp sign)");
}
while(defined(next_chr) and $ch =~ /\d/){
$n .= $ch;
}
}
$v .= $n;
if ($v !~ /[.eE]/ and length $v > $max_intsize) {
if ($allow_bigint) {
require Math::BigInt;
return Math::BigInt->new($v);
}
else {
return "$v";
}
}
elsif ($allow_bigint) {
require Math::BigFloat;
return Math::BigFloat->new($v);
}
return 0+$v;
}
sub is_valid_utf8 {
$utf8_len = $_[0] =~ /[\x00-\x7F]/  ? 1
: $_[0] =~ /[\xC2-\xDF]/  ? 2
: $_[0] =~ /[\xE0-\xEF]/  ? 3
: $_[0] =~ /[\xF0-\xF4]/  ? 4
: 0
;
return unless $utf8_len;
my $is_valid_utf8 = substr($text, $at - 1, $utf8_len);
return ( $is_valid_utf8 =~ /^(?:
[\x00-\x7F]
|[\xC2-\xDF][\x80-\xBF]
|[\xE0][\xA0-\xBF][\x80-\xBF]
|[\xE1-\xEC][\x80-\xBF][\x80-\xBF]
|[\xED][\x80-\x9F][\x80-\xBF]
|[\xEE-\xEF][\x80-\xBF][\x80-\xBF]
|[\xF0][\x90-\xBF][\x80-\xBF][\x80-\xBF]
|[\xF1-\xF3][\x80-\xBF][\x80-\xBF][\x80-\xBF]
|[\xF4][\x80-\x8F][\x80-\xBF][\x80-\xBF]
)$/x )  ? $is_valid_utf8 : '';
}
sub decode_error {
my $error  = shift;
my $no_rep = shift;
my $str    = defined $text ? substr($text, $at) : '';
my $mess   = '';
my $type   = $] >= 5.008           ? 'U*'
: $] <  5.006           ? 'C*'
: utf8::is_utf8( $str ) ? 'U*'
: 'C*'
;
for my $c ( unpack( $type, $str ) ) {
$mess .=  $c == 0x07 ? '\a'
: $c == 0x09 ? '\t'
: $c == 0x0a ? '\n'
: $c == 0x0d ? '\r'
: $c == 0x0c ? '\f'
: $c <  0x20 ? sprintf('\x{%x}', $c)
: $c == 0x5c ? '\\\\'
: $c <  0x80 ? chr($c)
: sprintf('\x{%x}', $c)
;
if ( length $mess >= 20 ) {
$mess .= '...';
last;
}
}
unless ( length $mess ) {
$mess = '(end of string)';
}
		print "JSON ERROR: $error : at character offset $at (before \"$mess\")";
}
sub _json_object_hook {
my $o    = $_[0];
my @ks = keys %{$o};
if ( $cb_sk_object and @ks == 1 and exists $cb_sk_object->{ $ks[0] } and ref $cb_sk_object->{ $ks[0] } ) {
my @val = $cb_sk_object->{ $ks[0] }->( $o->{$ks[0]} );
if (@val == 1) {
return $val[0];
}
}
my @val = $cb_object->($o) if ($cb_object);
if (@val == 0 or @val > 1) {
return $o;
}
else {
return $val[0];
}
}
sub PP_decode_box {
{
text    => $text,
at      => $at,
ch      => $ch,
len     => $len,
depth   => $depth,
encoding      => $encoding,
is_valid_utf8 => $is_valid_utf8,
};
}
}
sub _decode_surrogates {
my $uni = 0x10000 + (hex($_[0]) - 0xD800) * 0x400 + (hex($_[1]) - 0xDC00);
my $un  = pack('U*', $uni);
utf8::encode( $un );
return $un;
}
sub _decode_unicode {
my $un = pack('U', hex shift);
utf8::encode( $un );
return $un;
}
BEGIN {
unless ( defined &utf8::is_utf8 ) {
require Encode;
*utf8::is_utf8 = *Encode::is_utf8;
}
if ( $] >= 5.008 ) {
*JSON::PP::JSON_PP_encode_ascii      = \&_encode_ascii;
*JSON::PP::JSON_PP_encode_latin1     = \&_encode_latin1;
*JSON::PP::JSON_PP_decode_surrogates = \&_decode_surrogates;
*JSON::PP::JSON_PP_decode_unicode    = \&_decode_unicode;
}
if ($] >= 5.008 and $] < 5.008003) {
package JSON::PP;
require subs;
subs->import('join');
eval q|
sub join {
return '' if (@_ < 2);
my $j   = shift;
my $str = shift;
for (@_) { $str .= $j . $_; }
return $str;
}
|;
}
sub JSON::PP::incr_parse {
( $_[0]->{_incr_parser} ||= JSON::PP::IncrParser->new )->incr_parse( @_ );
}
sub JSON::PP::incr_skip {
( $_[0]->{_incr_parser} ||= JSON::PP::IncrParser->new )->incr_skip;
}
sub JSON::PP::incr_reset {
( $_[0]->{_incr_parser} ||= JSON::PP::IncrParser->new )->incr_reset;
}
eval q{
sub JSON::PP::incr_text : lvalue {
$_[0]->{_incr_parser} ||= JSON::PP::IncrParser->new;
if ( $_[0]->{_incr_parser}->{incr_parsing} ) {
print "JSON ERROR: incr_text can not be called when the incremental parser already started parsing\n";
}
$_[0]->{_incr_parser}->{incr_text};
}
} if ( $] >= 5.006 );
}
BEGIN {
eval 'require Scalar::Util';
unless($@){
*JSON::PP::blessed = \&Scalar::Util::blessed;
*JSON::PP::reftype = \&Scalar::Util::reftype;
*JSON::PP::refaddr = \&Scalar::Util::refaddr;
}
else{
eval 'sub UNIVERSAL::a_sub_not_likely_to_be_here { ref($_[0]) }';
*JSON::PP::blessed = sub {
local($@, $SIG{__DIE__}, $SIG{__WARN__});
ref($_[0]) ? eval { $_[0]->a_sub_not_likely_to_be_here } : undef;
};
my %tmap = qw(
B::NULL   SCALAR
B::HV     HASH
B::AV     ARRAY
B::CV     CODE
B::IO     IO
B::GV     GLOB
B::REGEXP REGEXP
);
*JSON::PP::reftype = sub {
my $r = shift;
return undef unless length(ref($r));
my $t = ref(B::svref_2object($r));
return
exists $tmap{$t} ? $tmap{$t}
: length(ref($$r)) ? 'REF'
:                    'SCALAR';
};
*JSON::PP::refaddr = sub {
return undef unless length(ref($_[0]));
my $addr;
if(defined(my $pkg = blessed($_[0]))) {
$addr .= bless $_[0], 'Scalar::Util::Fake';
bless $_[0], $pkg;
}
else {
$addr .= $_[0]
}
$addr =~ /0x(\w+)/;
local $^W;
hex($1);
}
}
}
$JSON::PP::true  = do { bless \(my $dummy = 1), "JSON::backportPP::Boolean" };
$JSON::PP::false = do { bless \(my $dummy = 0), "JSON::backportPP::Boolean" };
sub is_bool { defined $_[0] and UNIVERSAL::isa($_[0], "JSON::PP::Boolean"); }
sub true  { $JSON::PP::true  }
sub false { $JSON::PP::false }
sub null  { undef; }
package JSON::backportPP::Boolean;
@JSON::backportPP::Boolean::ISA = ('JSON::PP::Boolean');
use overload (
   "0+"     => sub { ${$_[0]} },
   "++"     => sub { $_[0] = ${$_[0]} + 1 },
   "--"     => sub { $_[0] = ${$_[0]} - 1 },
   fallback => 1,
);
package
JSON::PP::IncrParser;
use constant INCR_M_WS   => 0;
use constant INCR_M_STR  => 1;
use constant INCR_M_BS   => 2;
use constant INCR_M_JSON => 3;
use constant INCR_M_C0   => 4;
use constant INCR_M_C1   => 5;
$JSON::PP::IncrParser::VERSION = '1.01';
my $unpack_format = $] < 5.006 ? 'C*' : 'U*';
sub new {
my ( $class ) = @_;
bless {
incr_nest    => 0,
incr_text    => undef,
incr_parsing => 0,
incr_p       => 0,
}, $class;
}
sub incr_parse {
my ( $self, $coder, $text ) = @_;
$self->{incr_text} = '' unless ( defined $self->{incr_text} );
if ( defined $text ) {
if ( utf8::is_utf8( $text ) and !utf8::is_utf8( $self->{incr_text} ) ) {
utf8::upgrade( $self->{incr_text} ) ;
utf8::decode( $self->{incr_text} ) ;
}
$self->{incr_text} .= $text;
}
my $max_size = $coder->get_max_size;
if ( defined wantarray ) {
$self->{incr_mode} = INCR_M_WS unless defined $self->{incr_mode};
if ( wantarray ) {
my @ret;
$self->{incr_parsing} = 1;
do {
push @ret, $self->_incr_parse( $coder, $self->{incr_text} );
unless ( !$self->{incr_nest} and $self->{incr_mode} == INCR_M_JSON ) {
$self->{incr_mode} = INCR_M_WS if $self->{incr_mode} != INCR_M_STR;
}
} until ( length $self->{incr_text} >= $self->{incr_p} );
$self->{incr_parsing} = 0;
return @ret;
}
else {
$self->{incr_parsing} = 1;
my $obj = $self->_incr_parse( $coder, $self->{incr_text} );
$self->{incr_parsing} = 0 if defined $obj;
return $obj ? $obj : undef;
}
}
}
sub _incr_parse {
my ( $self, $coder, $text, $skip ) = @_;
my $p = $self->{incr_p};
my $restore = $p;
my @obj;
my $len = length $text;
if ( $self->{incr_mode} == INCR_M_WS ) {
while ( $len > $p ) {
my $s = substr( $text, $p, 1 );
$p++ and next if ( 0x20 >= unpack($unpack_format, $s) );
$self->{incr_mode} = INCR_M_JSON;
last;
}
}
while ( $len > $p ) {
my $s = substr( $text, $p++, 1 );
if ( $s eq '"' ) {
if (substr( $text, $p - 2, 1 ) eq '\\' ) {
next;
}
if ( $self->{incr_mode} != INCR_M_STR  ) {
$self->{incr_mode} = INCR_M_STR;
}
else {
$self->{incr_mode} = INCR_M_JSON;
unless ( $self->{incr_nest} ) {
last;
}
}
}
if ( $self->{incr_mode} == INCR_M_JSON ) {
if ( $s eq '[' or $s eq '{' ) {
if ( ++$self->{incr_nest} > $coder->get_max_depth ) {
print "JSON ERROR: json text or perl structure exceeds maximum nesting level (max_depth set too low?)\n";
}
}
elsif ( $s eq ']' or $s eq '}' ) {
last if ( --$self->{incr_nest} <= 0 );
}
elsif ( $s eq '#' ) {
while ( $len > $p ) {
last if substr( $text, $p++, 1 ) eq "\n";
}
}
}
}
$self->{incr_p} = $p;
return if ( $self->{incr_mode} == INCR_M_STR and not $self->{incr_nest} );
return if ( $self->{incr_mode} == INCR_M_JSON and $self->{incr_nest} > 0 );
return '' unless ( length substr( $self->{incr_text}, 0, $p ) );
$self->{incr_p} = $restore;
$self->{incr_c} = $p;
my ( $obj, $tail ) = $coder->PP_decode_json( substr( $self->{incr_text}, 0, $p ), 0x10000001 );
$self->{incr_text} = substr( $self->{incr_text}, $p );
$self->{incr_p} = 0;
return $obj or '';
}
sub incr_text {
if ( $_[0]->{incr_parsing} ) {
print "JSON ERROR: incr_text can not be called when the incremental parser already started parsing\n";
}
$_[0]->{incr_text};
}
sub incr_skip {
my $self  = shift;
$self->{incr_text} = substr( $self->{incr_text}, $self->{incr_c} );
$self->{incr_p} = 0;
}
sub incr_reset {
my $self = shift;
$self->{incr_text}    = undef;
$self->{incr_p}       = 0;
$self->{incr_mode}    = 0;
$self->{incr_nest}    = 0;
$self->{incr_parsing} = 0;
}
1;
