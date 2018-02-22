
var allLanguages = [ "aa","ab","ace","ae","aeb","af","aka","amh","ami","an","ar","arc","arq","arz","as","ase","ast","av","ay","az","ba","bam","be","bem","ber","bg","bh","bi","bn","bnt","bo","br","bs","bug","ca","cak","ce","ceb","ch","cho","chr","ckb","cku","cly","cnh","co","cr","crs","cs","cta","ctd","ctu","cu","cv","cy","czn","da","de","de-ch","dsb","dv","dz","ee","efi","el","en","en-gb","eo","es","es-419","es-ar","es-mx","es-ni","et","eu","fa","ff","fi","fil","fj","fo","fr","fr-ca","ful","fy-nl","ga","gd","gl","gn","got","gsw","gu","gv","hai","hau","haw","haz","hb","hch","he","hi","hmn","ho","hr","hsb","ht","hu","hup","hus","hwc","hy","hz","ia","ibo","id","ie","ii","ik","ilo","inh","io","iro","is","it","iu","ja","jv","ka","kaa","kar","kau","kik","kin","kj","kk","kl","km","kn","ko","kon","ks","ksh","ku","kv","kw","ky","la","lb","lg","li","lin","lkt","lld","lo","loz","lt","ltg","lu","lua","luo","lus","lut","luy","lv","mad","meta-audio","meta-geo","meta-tw","meta-video","meta-wiki","mfe","mh","mi","mk","ml","mlg","mn","mni","mnk","mo","moh","mos","mr","ms","mt","mus","my","na","nan","nb","nci","nd","ne","ng","nl","nn","nr","nso","nv","nya","oc","oji","or","orm","os","pam","pan","pap","pcd","pcm","pi","pl","pnb","prs","ps","pt","pt-br","que","qvi","raj","rar","rm","ro","ru","run","rup","ry","sa","sby","sc","scn","sco","sd","se","sg","sgn","sh","shp","si","sk","skx","sl","sm","sna","som","sot","sq","sr","sr-latn","srp","ss","su","sv","swa","szl","ta","tao","tar","te","tet","tg","th","tir","tk","tl","tlh","to","tob","toj","tr","trv","ts","tsn","tsz","tt","tw","ty","tzh","tzo","ug","uk","umb","ur","uz","ve","vi","vls","vo","wa","wau","wbl","wol","x-other","xho","yaq","yi","yor","yua","za","zam","zh","zh-cn","zh-hk","zh-sg","zh-tw","zul","zza" ];
var popularLanguages = ["ar","cs","da","de","el","en","es","fa","fr","hu","id","it","ja","ko","nl","pl","pt","pt-br","ro","ru","sv","th","tr","vi","zh-cn","zh-tw" ];
var languageNames = { "aa": "Afar [aa]","ab": "Abkhazian [ab]","ace": "Acehnese [ace]","ae": "Avestan [ae]","aeb": "Tunisian Arabic [aeb]","af": "Afrikaans [af]","aka": "Akan [aka]","amh": "Amharic [amh]","ami": "Amis [ami]","an": "Aragonese [an]","ar": "Arabic [ar]","arc": "Aramaic [arc]","arq": "Algerian Arabic [arq]","arz": "Egyptian Arabic [arz]","as": "Assamese [as]","ase": "American Sign Language [ase]","ast": "Asturian [ast]","av": "Avaric [av]","ay": "Aymara [ay]","az": "Azerbaijani [az]","ba": "Bashkir [ba]","bam": "Bambara [bam]","be": "Belarusian [be]","bem": "Bemba (Zambia) [bem]","ber": "Berber [ber]","bg": "Bulgarian [bg]","bh": "Bihari [bh]","bi": "Bislama [bi]","bn": "Bengali [bn]","bnt": "Ibibio [bnt]","bo": "Tibetan [bo]","br": "Breton [br]","bs": "Bosnian [bs]","bug": "Buginese [bug]","ca": "Catalan [ca]","cak": "Cakchiquel, Central [cak]","ce": "Chechen [ce]","ceb": "Cebuano [ceb]","ch": "Chamorro [ch]","cho": "Choctaw [cho]","chr": "Cherokee [chr]","ckb": "Kurdish (Central) [ckb]","cku": "Koasati [cku]","cly": "Eastern Chatino [cly]","cnh": "Hakha Chin [cnh]","co": "Corsican [co]","cr": "Cree [cr]","crs": "Seselwa Creole French [crs]","cs": "Czech [cs]","cta": "Tataltepec Chatino [cta]","ctd": "Chin, Tedim [ctd]","ctu": "Chol, Tumbalá [ctu]","cu": "Church Slavic [cu]","cv": "Chuvash [cv]","cy": "Welsh [cy]","czn": "Zenzontepec Chatino [czn]","da": "Danish [da]","de": "German [de]","de-ch": "German (Switzerland) [de-ch]","dsb": "Lower Sorbian [dsb]","dv": "Divehi [dv]","dz": "Dzongkha [dz]","ee": "Ewe [ee]","efi": "Efik [efi]","el": "Greek [el]","en": "English [en]","en-gb": "English, British [en-gb]","eo": "Esperanto [eo]","es": "Spanish [es]","es-419": "Spanish (Latin America) [es-419]","es-ar": "Spanish, Argentinian [es-ar]","es-mx": "Spanish, Mexican [es-mx]","es-ni": "Spanish, Nicaraguan [es-ni]","et": "Estonian [et]","eu": "Basque [eu]","fa": "Persian [fa]","ff": "Fulah [ff]","fi": "Finnish [fi]","fil": "Filipino [fil]","fj": "Fijian [fj]","fo": "Faroese [fo]","fr": "French [fr]","fr-ca": "French (Canada) [fr-ca]","ful": "Fula [ful]","fy-nl": "Frisian [fy-nl]","ga": "Irish [ga]","gd": "Scottish Gaelic [gd]","gl": "Galician [gl]","gn": "Guaran [gn]","got": "Gothic [got]","gsw": "Swiss German [gsw]","gu": "Gujarati [gu]","gv": "Manx [gv]","hai": "Haida [hai]","hau": "Hausa [hau]","haw": "Hawaiian [haw]","haz": "Hazaragi [haz]","hb": "HamariBoli (Roman Hindi-Urdu) [hb]","hch": "Huichol [hch]","he": "Hebrew [he]","hi": "Hindi [hi]","hmn": "Hmong [hmn]","ho": "Hiri Motu [ho]","hr": "Croatian [hr]","hsb": "Upper Sorbian [hsb]","ht": "Creole, Haitian [ht]","hu": "Hungarian [hu]","hup": "Hupa [hup]","hus": "Huastec, Veracruz [hus]","hwc": "Hawai'i Creole English [hwc]","hy": "Armenian [hy]","hz": "Herero [hz]","ia": "Interlingua [ia]","ibo": "Igbo [ibo]","id": "Indonesian [id]","ie": "Interlingue [ie]","ii": "Sichuan Yi [ii]","ik": "Inupia [ik]","ilo": "Ilocano [ilo]","inh": "Ingush [inh]","io": "Ido [io]","iro": "Iroquoian languages [iro]","is": "Icelandic [is]","it": "Italian [it]","iu": "Inuktitut [iu]","ja": "Japanese [ja]","jv": "Javanese [jv]","ka": "Georgian [ka]","kaa": "Karakalpak [kaa]","kar": "Karen [kar]","kau": "Kanuri [kau]","kik": "Gikuyu [kik]","kin": "Rwandi [kin]","kj": "Kuanyama, Kwanyama [kj]","kk": "Kazakh [kk]","kl": "Greenlandic [kl]","km": "Khmer [km]","kn": "Kannada [kn]","ko": "Korean [ko]","kon": "Kongo [kon]","ks": "Kashmiri [ks]","ksh": "Colognian [ksh]","ku": "Kurdish [ku]","kv": "Komi [kv]","kw": "Cornish [kw]","ky": "Kyrgyz [ky]","la": "Latin [la]","lb": "Luxembourgish [lb]","lg": "Ganda [lg]","li": "Limburgish [li]","lin": "Lingala [lin]","lkt": "Lakota [lkt]","lld": "Ladin [lld]","lo": "Lao [lo]","loz": "Lozi [loz]","lt": "Lithuanian [lt]","ltg": "Latgalian [ltg]","lu": "Luba-Katagana [lu]","lua": "Luba-Kasai [lua]","luo": "Luo [luo]","lus": "Mizo [lus]","lut": "Lushootseed [lut]","luy": "Luhya [luy]","lv": "Latvian [lv]","mad": "Madurese [mad]","meta-audio": "Metadata: Audio Description [meta-audio]","meta-geo": "Metadata: Geo [meta-geo]","meta-tw": "Metadata: Twitter [meta-tw]","meta-video": "Metadata: Video Description [meta-video]","meta-wiki": "Metadata: Wikipedia [meta-wiki]","mfe": "Mauritian Creole [mfe]","mh": "Marshallese [mh]","mi": "Maori [mi]","mk": "Macedonian [mk]","ml": "Malayalam [ml]","mlg": "Malagasy [mlg]","mn": "Mongolian [mn]","mni": "Manipuri [mni]","mnk": "Mandinka [mnk]","mo": "Moldavian, Moldovan [mo]","moh": "Mohawk [moh]","mos": "Mossi [mos]","mr": "Marathi [mr]","ms": "Malay [ms]","mt": "Maltese [mt]","mus": "Muscogee [mus]","my": "Burmese [my]","na": "Naurunan [na]","nan": "Hokkien [nan]","nb": "Norwegian Bokmal [nb]","nci": "Nahuatl, Classical [nci]","nd": "North Ndebele [nd]","ne": "Nepali [ne]","ng": "Ndonga [ng]","nl": "Dutch [nl]","nn": "Norwegian Nynorsk [nn]","nr": "Southern Ndebele [nr]","nso": "Northern Sotho [nso]","nv": "Navajo [nv]","nya": "Chewa [nya]","oc": "Occitan [oc]","oji": "Ojibwe [oji]","or": "Oriya [or]","orm": "Oromo [orm]","os": "Ossetian, Ossetic [os]","pam": "Kapampangan [pam]","pan": "Punjabi [pan]","pap": "Papiamento [pap]","pcd": "Picard [pcd]","pcm": "Nigerian Pidgin [pcm]","pi": "Pali [pi]","pl": "Polish [pl]","pnb": "Western Punjabi [pnb]","prs": "Dari [prs]","ps": "Pashto [ps]","pt": "Portuguese [pt]","pt-br": "Portuguese, Brazilian [pt-br]","que": "Quechua [que]","qvi": "Quichua, Imbabura Highland [qvi]","raj": "Rajasthani [raj]","rar": "Cook Islands Māori [rar]","rm": "Romansh [rm]","ro": "Romanian [ro]","ru": "Russian [ru]","run": "Rundi [run]","rup": "Macedo [rup]","ry": "Rusyn [ry]","sa": "Sanskrit [sa]","sby": "Soli [sby]","sc": "Sardinian [sc]","scn": "Sicilian [scn]","sco": "Scots [sco]","sd": "Sindhi [sd]","se": "Northern Sami [se]","sg": "Sango [sg]","sgn": "Sign Languages [sgn]","sh": "Serbo-Croatian [sh]","shp": "Shipibo-Conibo [shp]","si": "Sinhala [si]","sk": "Slovak [sk]","skx": "Seko Padang [skx]","sl": "Slovenian [sl]","sm": "Samoan [sm]","sna": "Shona [sna]","som": "Somali [som]","sot": "Sotho [sot]","sq": "Albanian [sq]","sr": "Serbian [sr]","sr-latn": "Serbian, Latin [sr-latn]","srp": "Montenegrin [srp]","ss": "Swati [ss]","su": "Sundanese [su]","sv": "Swedish [sv]","swa": "Swahili [swa]","szl": "Silesian [szl]","ta": "Tamil [ta]","tao": "Yami (Tao) [tao]","tar": "Tarahumara, Central [tar]","te": "Telugu [te]","tet": "Tetum [tet]","tg": "Tajik [tg]","th": "Thai [th]","tir": "Tigrinya [tir]","tk": "Turkmen [tk]","tl": "Tagalog [tl]","tlh": "Klingon [tlh]","to": "Tonga [to]","tob": "Qom (Toba) [tob]","toj": "Tojolabal [toj]","tr": "Turkish [tr]","trv": "Seediq [trv]","ts": "Tsonga [ts]","tsn": "Tswana [tsn]","tsz": "Purepecha [tsz]","tt": "Tatar [tt]","tw": "Twi [tw]","ty": "Tahitian [ty]","tzh": "Tzeltal, Oxchuc [tzh]","tzo": "Tzotzil, Venustiano Carranza [tzo]","ug": "Uyghur [ug]","uk": "Ukrainian [uk]","umb": "Umbundu [umb]","ur": "Urdu [ur]","uz": "Uzbek [uz]","ve": "Venda [ve]","vi": "Vietnamese [vi]","vls": "Flemish [vls]","vo": "Volapuk [vo]","wa": "Walloon [wa]","wau": "Wauja [wau]","wbl": "Wakhi [wbl]","wol": "Wolof [wol]","x-other": "Other [x-other]","xho": "Xhosa [xho]","yaq": "Yaqui [yaq]","yi": "Yiddish [yi]","yor": "Yoruba [yor]","yua": "Maya, Yucatán [yua]","za": "Zhuang, Chuang [za]","zam": "Zapotec, Miahuatlán [zam]","zh": "Chinese, Yue [zh]","zh-cn": "Chinese, Simplified [zh-cn]","zh-hk": "Chinese, Traditional (Hong Kong) [zh-hk]","zh-sg": "Chinese, Simplified (Singaporean) [zh-sg]","zh-tw": "Chinese, Traditional [zh-tw]","zul": "Zulu [zul]","zza": "Zazaki [zza]" };
var localeChoices = { "ar":1,"ast":1,"az-az":1,"be":1,"bg":1,"bn":1,"bs":1,"ca":1,"cs":1,"cy":1,"da":1,"de":1,"el":1,"en":1,"en-gb":1,"eo":1,"es":1,"es-ar":1,"es-mx":1,"et":1,"eu":1,"fa":1,"fi":1,"fr":1,"fy-nl":1,"ga":1,"gl":1,"he":1,"hi":1,"hr":1,"hu":1,"hy":1,"ia":1,"id":1,"is":1,"it":1,"ja":1,"ka":1,"kk":1,"km":1,"kn":1,"ko":1,"ku":1,"ky":1,"lt":1,"lv":1,"mk":1,"ml":1,"mn":1,"mr":1,"ms":1,"my":1,"nb":1,"nl":1,"nn":1,"pl":1,"ps":1,"pt":1,"pt-br":1,"ro":1,"ru":1,"sco":1,"sk":1,"sl":1,"sq":1,"sr":1,"sr-latn":1,"sv":1,"ta":1,"te":1,"th":1,"tr":1,"ug":1,"uk":1,"ur":1,"uz":1,"vi":1,"zh":1,"zh-cn":1,"zh-tw":1 };

var allLanguagesLabel = "All Languages";
var popularLanguagesLabel = "Popular Languages";

function getLanguageName(languageCode) {
    return languageNames[languageCode];
}