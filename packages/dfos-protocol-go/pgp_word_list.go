package dfos

import "strings"

// THE PGP WORD LIST — TWO TABLES OF 256 PHONETICALLY DISTINCT WORDS.
//
// Byte-twin of dfos-protocol/src/key-proof/pgp-word-list.ts.
//
// The list was designed in 1995 by Patrick Juola and Philip Zimmermann for
// PGPfone, so two humans reading a fingerprint to each other over a voice channel
// could tell the words apart under noise: the candidates were drawn from Grady
// Ward's Moby Pronunciator and refined by a genetic search for maximum separation
// in phoneme space. It is a fixed historical table, not a parameter — these 512
// words in this order ARE the list, and the identical table appears in PGP's own
// "biometric fingerprint" display, in ZRTP/Zfone, and in every other tool that
// renders bytes for a human to read aloud.
//
// WHY TWO TABLES AND NOT ONE. Reading a long word sequence aloud invites exactly
// three errors — transposing two neighbors, duplicating a word, dropping one — and
// a single 256-word table detects none of them. Two tables do: the even table
// renders bytes at even offsets, the odd table bytes at odd offsets, so the
// reading alternates two-syllable, three-syllable, two-syllable. A transposed pair
// puts a three-syllable word where the listener expects two, and the error is
// audible without anyone comparing meanings. That alternation is the entire
// security property of the encoding, and it is why an implementation may not pick
// one table and use it throughout.
//
// The tables are disjoint — no word appears in both — so the syllable count alone
// identifies which offset parity a word came from.
//
// CASE. The published tables capitalize proper nouns (Belfast, Istanbul, Pluto).
// These are lowercased, because a fingerprint is compared by eye across two
// surfaces and case is a difference a human is asked to ignore; a table that is
// already uniform never poses the question. The lowercasing collides nothing —
// both tables still hold 256 distinct words after it.

// pgpEvenWords is the EVEN table: the two-syllable words, indexed by byte value,
// rendering bytes at even offsets (0, 2, 4, …).
var pgpEvenWords = [256]string{
	"aardvark", "absurd", "accrue", "acme", // 00
	"adrift", "adult", "afflict", "ahead", // 04
	"aimless", "algol", "allow", "alone", // 08
	"ammo", "ancient", "apple", "artist", // 0c
	"assume", "athens", "atlas", "aztec", // 10
	"baboon", "backfield", "backward", "banjo", // 14
	"beaming", "bedlamp", "beehive", "beeswax", // 18
	"befriend", "belfast", "berserk", "billiard", // 1c
	"bison", "blackjack", "blockade", "blowtorch", // 20
	"bluebird", "bombast", "bookshelf", "brackish", // 24
	"breadline", "breakup", "brickyard", "briefcase", // 28
	"burbank", "button", "buzzard", "cement", // 2c
	"chairlift", "chatter", "checkup", "chisel", // 30
	"choking", "chopper", "christmas", "clamshell", // 34
	"classic", "classroom", "cleanup", "clockwork", // 38
	"cobra", "commence", "concert", "cowbell", // 3c
	"crackdown", "cranky", "crowfoot", "crucial", // 40
	"crumpled", "crusade", "cubic", "dashboard", // 44
	"deadbolt", "deckhand", "dogsled", "dragnet", // 48
	"drainage", "dreadful", "drifter", "dropper", // 4c
	"drumbeat", "drunken", "dupont", "dwelling", // 50
	"eating", "edict", "egghead", "eightball", // 54
	"endorse", "endow", "enlist", "erase", // 58
	"escape", "exceed", "eyeglass", "eyetooth", // 5c
	"facial", "fallout", "flagpole", "flatfoot", // 60
	"flytrap", "fracture", "framework", "freedom", // 64
	"frighten", "gazelle", "geiger", "glitter", // 68
	"glucose", "goggles", "goldfish", "gremlin", // 6c
	"guidance", "hamlet", "highchair", "hockey", // 70
	"indoors", "indulge", "inverse", "involve", // 74
	"island", "jawbone", "keyboard", "kickoff", // 78
	"kiwi", "klaxon", "locale", "lockup", // 7c
	"merit", "minnow", "miser", "mohawk", // 80
	"mural", "music", "necklace", "neptune", // 84
	"newborn", "nightbird", "oakland", "obtuse", // 88
	"offload", "optic", "orca", "payday", // 8c
	"peachy", "pheasant", "physique", "playhouse", // 90
	"pluto", "preclude", "prefer", "preshrunk", // 94
	"printer", "prowler", "pupil", "puppy", // 98
	"python", "quadrant", "quiver", "quota", // 9c
	"ragtime", "ratchet", "rebirth", "reform", // a0
	"regain", "reindeer", "rematch", "repay", // a4
	"retouch", "revenge", "reward", "rhythm", // a8
	"ribcage", "ringbolt", "robust", "rocker", // ac
	"ruffled", "sailboat", "sawdust", "scallion", // b0
	"scenic", "scorecard", "scotland", "seabird", // b4
	"select", "sentence", "shadow", "shamrock", // b8
	"showgirl", "skullcap", "skydive", "slingshot", // bc
	"slowdown", "snapline", "snapshot", "snowcap", // c0
	"snowslide", "solo", "southward", "soybean", // c4
	"spaniel", "spearhead", "spellbind", "spheroid", // c8
	"spigot", "spindle", "spyglass", "stagehand", // cc
	"stagnate", "stairway", "standard", "stapler", // d0
	"steamship", "sterling", "stockman", "stopwatch", // d4
	"stormy", "sugar", "surmount", "suspense", // d8
	"sweatband", "swelter", "tactics", "talon", // dc
	"tapeworm", "tempest", "tiger", "tissue", // e0
	"tonic", "topmost", "tracker", "transit", // e4
	"trauma", "treadmill", "trojan", "trouble", // e8
	"tumor", "tunnel", "tycoon", "uncut", // ec
	"unearth", "unwind", "uproot", "upset", // f0
	"upshot", "vapor", "village", "virus", // f4
	"vulcan", "waffle", "wallet", "watchword", // f8
	"wayside", "willow", "woodlark", "zulu", // fc
}

// pgpOddWords is the ODD table: the three-syllable words, indexed by byte value,
// rendering bytes at odd offsets (1, 3, 5, …).
var pgpOddWords = [256]string{
	"adroitness", "adviser", "aftermath", "aggregate", // 00
	"alkali", "almighty", "amulet", "amusement", // 04
	"antenna", "applicant", "apollo", "armistice", // 08
	"article", "asteroid", "atlantic", "atmosphere", // 0c
	"autopsy", "babylon", "backwater", "barbecue", // 10
	"belowground", "bifocals", "bodyguard", "bookseller", // 14
	"borderline", "bottomless", "bradbury", "bravado", // 18
	"brazilian", "breakaway", "burlington", "businessman", // 1c
	"butterfat", "camelot", "candidate", "cannonball", // 20
	"capricorn", "caravan", "caretaker", "celebrate", // 24
	"cellulose", "certify", "chambermaid", "cherokee", // 28
	"chicago", "clergyman", "coherence", "combustion", // 2c
	"commando", "company", "component", "concurrent", // 30
	"confidence", "conformist", "congregate", "consensus", // 34
	"consulting", "corporate", "corrosion", "councilman", // 38
	"crossover", "crucifix", "cumbersome", "customer", // 3c
	"dakota", "decadence", "december", "decimal", // 40
	"designing", "detector", "detergent", "determine", // 44
	"dictator", "dinosaur", "direction", "disable", // 48
	"disbelief", "disruptive", "distortion", "document", // 4c
	"embezzle", "enchanting", "enrollment", "enterprise", // 50
	"equation", "equipment", "escapade", "eskimo", // 54
	"everyday", "examine", "existence", "exodus", // 58
	"fascinate", "filament", "finicky", "forever", // 5c
	"fortitude", "frequency", "gadgetry", "galveston", // 60
	"getaway", "glossary", "gossamer", "graduate", // 64
	"gravity", "guitarist", "hamburger", "hamilton", // 68
	"handiwork", "hazardous", "headwaters", "hemisphere", // 6c
	"hesitate", "hideaway", "holiness", "hurricane", // 70
	"hydraulic", "impartial", "impetus", "inception", // 74
	"indigo", "inertia", "infancy", "inferno", // 78
	"informant", "insincere", "insurgent", "integrate", // 7c
	"intention", "inventive", "istanbul", "jamaica", // 80
	"jupiter", "leprosy", "letterhead", "liberty", // 84
	"maritime", "matchmaker", "maverick", "medusa", // 88
	"megaton", "microscope", "microwave", "midsummer", // 8c
	"millionaire", "miracle", "misnomer", "molasses", // 90
	"molecule", "montana", "monument", "mosquito", // 94
	"narrative", "nebula", "newsletter", "norwegian", // 98
	"october", "ohio", "onlooker", "opulent", // 9c
	"orlando", "outfielder", "pacific", "pandemic", // a0
	"pandora", "paperweight", "paragon", "paragraph", // a4
	"paramount", "passenger", "pedigree", "pegasus", // a8
	"penetrate", "perceptive", "performance", "pharmacy", // ac
	"phonetic", "photograph", "pioneer", "pocketful", // b0
	"politeness", "positive", "potato", "processor", // b4
	"provincial", "proximate", "puberty", "publisher", // b8
	"pyramid", "quantity", "racketeer", "rebellion", // bc
	"recipe", "recover", "repellent", "replica", // c0
	"reproduce", "resistor", "responsive", "retraction", // c4
	"retrieval", "retrospect", "revenue", "revival", // c8
	"revolver", "sandalwood", "sardonic", "saturday", // cc
	"savagery", "scavenger", "sensation", "sociable", // d0
	"souvenir", "specialist", "speculate", "stethoscope", // d4
	"stupendous", "supportive", "surrender", "suspicious", // d8
	"sympathy", "tambourine", "telephone", "therapist", // dc
	"tobacco", "tolerance", "tomorrow", "torpedo", // e0
	"tradition", "travesty", "trombonist", "truncated", // e4
	"typewriter", "ultimate", "undaunted", "underfoot", // e8
	"unicorn", "unify", "universe", "unravel", // ec
	"upcoming", "vacancy", "vagabond", "vertigo", // f0
	"virginia", "visitor", "vocalist", "voyager", // f4
	"warranty", "waterloo", "whimsical", "wichita", // f8
	"wilmington", "wyoming", "yesteryear", "yucatan", // fc
}

// pgpWords renders octets as PGP words: byte i through the EVEN table when i is
// even and the ODD table when i is odd, space-joined. Total over any input —
// every byte value indexes both tables — so it never returns an empty word.
//
// This is the raw encoding, over any octets. KeyWordFingerprint is the one caller
// the protocol defines for it.
func pgpWords(data []byte) string {
	words := make([]string, len(data))
	for i, b := range data {
		if i%2 == 0 {
			words[i] = pgpEvenWords[b]
		} else {
			words[i] = pgpOddWords[b]
		}
	}
	return strings.Join(words, " ")
}
