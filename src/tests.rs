// Copyright 2012-2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[test]
fn test_general_security_profile_identifier_allowed() {
    use crate::GeneralSecurityProfile;
    assert_eq!(GeneralSecurityProfile::identifier_allowed('A'), true);
    assert_eq!('A'.identifier_allowed(), true);
    assert_eq!(GeneralSecurityProfile::identifier_allowed('0'), true);
    assert_eq!('0'.identifier_allowed(), true);
    assert_eq!(GeneralSecurityProfile::identifier_allowed('_'), true);
    assert_eq!('_'.identifier_allowed(), true);
    assert_eq!(GeneralSecurityProfile::identifier_allowed('\x00'), false);
    assert_eq!('\x00'.identifier_allowed(), false);
    // U+00B5 MICRO SIGN
    assert_eq!(GeneralSecurityProfile::identifier_allowed('µ'), false);
    assert_eq!('µ'.identifier_allowed(), false);
    // U+2160 ROMAN NUMERAL ONE
    assert_eq!(GeneralSecurityProfile::identifier_allowed('Ⅰ'), false);
    assert_eq!('Ⅰ'.identifier_allowed(), false);
}

#[test]
fn test_mixed_script() {
    use crate::MixedScript;
    assert_eq!("".is_single_script(), true);
    assert_eq!("".resolve_script_set().is_empty(), false);
    assert_eq!("".resolve_script_set().is_all(), true);
    assert_eq!("A".is_single_script(), true);
    assert_eq!("A".resolve_script_set().is_empty(), false);
    assert_eq!("A".resolve_script_set().is_all(), false);
    assert_eq!("A0".is_single_script(), true);
    assert_eq!("A0".resolve_script_set().is_empty(), false);
    assert_eq!("A0".resolve_script_set().is_all(), false);
    assert_eq!("0.".is_single_script(), true);
    assert_eq!("0.".resolve_script_set().is_empty(), false);
    assert_eq!("0.".resolve_script_set().is_all(), true);
    assert_eq!("福".is_single_script(), true);
    assert_eq!("福".resolve_script_set().is_empty(), false);
    assert_eq!("福".resolve_script_set().is_all(), false);
    assert_eq!("冬の雪".is_single_script(), true);
    assert_eq!("冬の雪".resolve_script_set().is_empty(), false);
    assert_eq!("冬の雪".resolve_script_set().is_all(), false);
    assert_eq!("幻ㄒㄧㄤ".is_single_script(), true);
    assert_eq!("幻ㄒㄧㄤ".resolve_script_set().is_empty(), false);
    assert_eq!("幻ㄒㄧㄤ".resolve_script_set().is_all(), false);
    assert_eq!("日出은".is_single_script(), true);
    assert_eq!("日出은".resolve_script_set().is_empty(), false);
    assert_eq!("日出은".resolve_script_set().is_all(), false);
    assert_eq!("夏の幻ㄒㄧㄤ".is_single_script(), false);
    assert_eq!("夏の幻ㄒㄧㄤ".resolve_script_set().is_empty(), true);
    assert_eq!("夏の幻ㄒㄧㄤ".resolve_script_set().is_all(), false);
}

#[test]
fn test_confusable_detection() {
    use crate::skeleton;
    use std::string::String;
    assert_eq!(&skeleton("").collect::<String>(), "");
    assert_eq!(&skeleton("ｓ").collect::<String>(), "s");
    assert_eq!(&skeleton("ｓｓｓ").collect::<String>(), "sss");
    assert_eq!(&skeleton("ﶛ").collect::<String>(), "نمى");
    assert_eq!(&skeleton("ﶛﶛ").collect::<String>(), "نمىنمى");
}

#[test]
fn test_confusable_detection_covers_rustc_punctuation() {
    use crate::skeleton;
    use std::iter::FromIterator;
    use std::string::String;
    
    #[rustfmt::skip] // for line breaks
    const UNICODE_ARRAY1: &[(char, &str, char)] = &[
        (' ', "Line Separator", ' '),
        (' ', "Paragraph Separator", ' '),
        (' ', "Ogham Space mark", ' '),
        (' ', "En Quad", ' '),
        (' ', "Em Quad", ' '),
        (' ', "En Space", ' '),
        (' ', "Em Space", ' '),
        (' ', "Three-Per-Em Space", ' '),
        (' ', "Four-Per-Em Space", ' '),
        (' ', "Six-Per-Em Space", ' '),
        (' ', "Punctuation Space", ' '),
        (' ', "Thin Space", ' '),
        (' ', "Hair Space", ' '),
        (' ', "Medium Mathematical Space", ' '),
        (' ', "No-Break Space", ' '),
        (' ', "Figure Space", ' '),
        (' ', "Narrow No-Break Space", ' '),

        ('ߺ', "Nko Lajanyalan", '_'),
        ('﹍', "Dashed Low Line", '_'),
        ('﹎', "Centreline Low Line", '_'),
        ('﹏', "Wavy Low Line", '_'),

        ('‐', "Hyphen", '-'),
        ('‑', "Non-Breaking Hyphen", '-'),
        ('‒', "Figure Dash", '-'),
        ('–', "En Dash", '-'),
        ('﹘', "Small Em Dash", '-'),
        ('۔', "Arabic Full Stop", '-'),
        ('⁃', "Hyphen Bullet", '-'),
        ('˗', "Modifier Letter Minus Sign", '-'),
        ('−', "Minus Sign", '-'),
        ('➖', "Heavy Minus Sign", '-'),
        ('Ⲻ', "Coptic Letter Dialect-P Ni", '-'),

        ('؍', "Arabic Date Separator", ','),
        ('٫', "Arabic Decimal Separator", ','),
        ('‚', "Single Low-9 Quotation Mark", ','),
        ('¸', "Cedilla", ','),
        ('ꓹ', "Lisu Letter Tone Na Po", ','),

        (';', "Greek Question Mark", ';'),

        ('ः', "Devanagari Sign Visarga", ':'),
        ('ઃ', "Gujarati Sign Visarga", ':'),
        ('։', "Armenian Full Stop", ':'),
        ('܃', "Syriac Supralinear Colon", ':'),
        ('܄', "Syriac Sublinear Colon", ':'),
        ('᛬', "Runic Multiple Punctuation", ':'),
        ('︰', "Presentation Form For Vertical Two Dot Leader", ':'),
        ('᠃', "Mongolian Full Stop", ':'),
        ('᠉', "Mongolian Manchu Full Stop", ':'),
        ('⁚', "Two Dot Punctuation", ':'),
        ('׃', "Hebrew Punctuation Sof Pasuq", ':'),
        ('˸', "Modifier Letter Raised Colon", ':'),
        ('꞉', "Modifier Letter Colon", ':'),
        ('∶', "Ratio", ':'),
        ('ː', "Modifier Letter Triangular Colon", ':'),
        ('ꓽ', "Lisu Letter Tone Mya Jeu", ':'),
        ('：', "Fullwidth Colon", ':'),

        ('！', "Fullwidth Exclamation Mark", '!'),
        ('ǃ', "Latin Letter Retroflex Click", '!'),
        ('ⵑ', "Tifinagh Letter Tuareg Yang", '!'),

        ('ʔ', "Latin Letter Glottal Stop", '?'),
        ('Ɂ', "Latin Capital Letter Glottal Stop", '?'),
        ('ॽ', "Devanagari Letter Glottal Stop", '?'),
        ('Ꭾ', "Cherokee Letter He", '?'),
        ('ꛫ', "Bamum Letter Ntuu", '?'),

        ('𝅭', "Musical Symbol Combining Augmentation Dot", '.'),
        ('․', "One Dot Leader", '.'),
        ('܁', "Syriac Supralinear Full Stop", '.'),
        ('܂', "Syriac Sublinear Full Stop", '.'),
        ('꘎', "Vai Full Stop", '.'),
        ('𐩐', "Kharoshthi Punctuation Dot", '.'),
        ('٠', "Arabic-Indic Digit Zero", '.'),
        ('۰', "Extended Arabic-Indic Digit Zero", '.'),
        ('ꓸ', "Lisu Letter Tone Mya Ti", '.'),

        ('՝', "Armenian Comma", '\''),
        ('＇', "Fullwidth Apostrophe", '\''),
        ('‘', "Left Single Quotation Mark", '\''),
        ('’', "Right Single Quotation Mark", '\''),
        ('‛', "Single High-Reversed-9 Quotation Mark", '\''),
        ('′', "Prime", '\''),
        ('‵', "Reversed Prime", '\''),
        ('՚', "Armenian Apostrophe", '\''),
        ('׳', "Hebrew Punctuation Geresh", '\''),
        ('`', "Grave Accent", '\''),
        ('`', "Greek Varia", '\''),
        ('｀', "Fullwidth Grave Accent", '\''),
        ('´', "Acute Accent", '\''),
        ('΄', "Greek Tonos", '\''),
        ('´', "Greek Oxia", '\''),
        ('᾽', "Greek Koronis", '\''),
        ('᾿', "Greek Psili", '\''),
        ('῾', "Greek Dasia", '\''),
        ('ʹ', "Modifier Letter Prime", '\''),
        ('ʹ', "Greek Numeral Sign", '\''),
        ('ˈ', "Modifier Letter Vertical Line", '\''),
        ('ˊ', "Modifier Letter Acute Accent", '\''),
        ('ˋ', "Modifier Letter Grave Accent", '\''),
        ('˴', "Modifier Letter Middle Grave Accent", '\''),
        ('ʻ', "Modifier Letter Turned Comma", '\''),
        ('ʽ', "Modifier Letter Reversed Comma", '\''),
        ('ʼ', "Modifier Letter Apostrophe", '\''),
        ('ʾ', "Modifier Letter Right Half Ring", '\''),
        ('ꞌ', "Latin Small Letter Saltillo", '\''),
        ('י', "Hebrew Letter Yod", '\''),
        ('ߴ', "Nko High Tone Apostrophe", '\''),
        ('ߵ', "Nko Low Tone Apostrophe", '\''),
        ('ᑊ', "Canadian Syllabics West-Cree P", '\''),
        ('ᛌ', "Runic Letter Short-Twig-Sol S", '\''),
        ('𖽑', "Miao Sign Aspiration", '\''),
        ('𖽒', "Miao Sign Reformed Voicing", '\''),

        ('᳓', "Vedic Sign Nihshvasa", '"'),
        ('＂', "Fullwidth Quotation Mark", '"'),
        ('“', "Left Double Quotation Mark", '"'),
        ('”', "Right Double Quotation Mark", '"'),
        ('‟', "Double High-Reversed-9 Quotation Mark", '"'),
        ('″', "Double Prime", '"'),
        ('‶', "Reversed Double Prime", '"'),
        ('〃', "Ditto Mark", '"'),
        ('״', "Hebrew Punctuation Gershayim", '"'),
        ('˝', "Double Acute Accent", '"'),
        ('ʺ', "Modifier Letter Double Prime", '"'),
        ('˶', "Modifier Letter Middle Double Acute Accent", '"'),
        ('ˮ', "Modifier Letter Double Apostrophe", '"'),
        ('ײ', "Hebrew Ligature Yiddish Double Yod", '"'),

        ('❨', "Medium Left Parenthesis Ornament", '('),
        ('﴾', "Ornate Left Parenthesis", '('),

        ('❩', "Medium Right Parenthesis Ornament", ')'),
        ('﴿', "Ornate Right Parenthesis", ')'),


        ('❴', "Medium Left Curly Bracket Ornament", '{'),
        ('𝄔', "Musical Symbol Brace", '{'),

        ('❵', "Medium Right Curly Bracket Ornament", '}'),

        ('⁎', "Low Asterisk", '*'),
        ('٭', "Arabic Five Pointed Star", '*'),
        ('∗', "Asterisk Operator", '*'),
        ('𐌟', "Old Italic Letter Ess", '*'),

        ('᜵', "Philippine Single Punctuation", '/'),
        ('⁁', "Caret Insertion Point", '/'),
        ('∕', "Division Slash", '/'),
        ('⁄', "Fraction Slash", '/'),
        ('╱', "Box Drawings Light Diagonal Upper Right To Lower Left", '/'),
        ('⟋', "Mathematical Rising Diagonal", '/'),
        ('⧸', "Big Solidus", '/'),
        ('𝈺', "Greek Instrumental Notation Symbol-47", '/'),
        ('㇓', "CJK Stroke Sp", '/'),
        ('〳', "Vertical Kana Repeat Mark Upper Half", '/'),
        ('Ⳇ', "Coptic Capital Letter Old Coptic Esh", '/'),
        ('ノ', "Katakana Letter No", '/'),
        ('丿', "CJK Unified Ideograph-4E3F", '/'),
        ('⼃', "Kangxi Radical Slash", '/'),

        ('＼', "Fullwidth Reverse Solidus", '\\'),
        ('﹨', "Small Reverse Solidus", '\\'),
        ('∖', "Set Minus", '\\'),
        ('⟍', "Mathematical Falling Diagonal", '\\'),
        ('⧵', "Reverse Solidus Operator", '\\'),
        ('⧹', "Big Reverse Solidus", '\\'),
        ('⧹', "Greek Vocal Notation Symbol-16", '\\'),
        ('⧹', "Greek Instrumental Symbol-48", '\\'),
        ('㇔', "CJK Stroke D", '\\'),
        ('丶', "CJK Unified Ideograph-4E36", '\\'),
        ('⼂', "Kangxi Radical Dot", '\\'),

        ('ꝸ', "Latin Small Letter Um", '&'),

        ('᛭', "Runic Cross Punctuation", '+'),
        ('➕', "Heavy Plus Sign", '+'),
        ('𐊛', "Lycian Letter H", '+'),

        ('‹', "Single Left-Pointing Angle Quotation Mark", '<'),
        ('❮', "Heavy Left-Pointing Angle Quotation Mark Ornament", '<'),
        ('˂', "Modifier Letter Left Arrowhead", '<'),
        ('𝈶', "Greek Instrumental Symbol-40", '<'),
        ('ᐸ', "Canadian Syllabics Pa", '<'),
        ('ᚲ', "Runic Letter Kauna", '<'),

        ('᐀', "Canadian Syllabics Hyphen", '='),
        ('⹀', "Double Hyphen", '='),
        ('゠', "Katakana-Hiragana Double Hyphen", '='),
        ('꓿', "Lisu Punctuation Full Stop", '='),

        ('›', "Single Right-Pointing Angle Quotation Mark", '>'),
        ('❯', "Heavy Right-Pointing Angle Quotation Mark Ornament", '>'),
        ('˃', "Modifier Letter Right Arrowhead", '>'),
        ('𝈷', "Greek Instrumental Symbol-42", '>'),
        ('ᐳ', "Canadian Syllabics Po", '>'),
        ('𖼿', "Miao Letter Archaic Zza", '>'),
    ];
    for (fst, _, snd) in UNICODE_ARRAY1 {
        let fst_str = String::from_iter(Some(fst));
        let snd_str = String::from_iter(Some(snd));
        let fst_skeleton = skeleton(&fst_str).collect::<String>();
        let snd_skeleton = skeleton(&snd_str).collect::<String>();
        if fst_skeleton != snd_skeleton {
            println!("{:?} and {:?} pair is not contained!", fst, snd);
        }
    }
}

#[test]
fn test_confusable_detection_rustc_specific_punctuation() {
    use crate::skeleton;
    use std::iter::FromIterator;
    use std::string::String;
    
    #[rustfmt::skip] // for line breaks
    const UNICODE_ARRAY2: &[(char, &str, char)] = &[
       ('　', "Ideographic Space", ' '),

       ('＿', "Fullwidth Low Line", '_'),

       ('—', "Em Dash", '-'),
       ('ー', "Katakana-Hiragana Prolonged Sound Mark", '-'),
       ('－', "Fullwidth Hyphen-Minus", '-'),
       ('―', "Horizontal Bar", '-'),
       ('─', "Box Drawings Light Horizontal", '-'),
       ('━', "Box Drawings Heavy Horizontal", '-'),
       ('㇐', "CJK Stroke H", '-'),
       ('ꟷ', "Latin Epigraphic Letter Sideways I", '-'),
       ('ᅳ', "Hangul Jungseong Eu", '-'),
       ('ㅡ', "Hangul Letter Eu", '-'),
       ('一', "CJK Unified Ideograph-4E00", '-'),
       ('⼀', "Kangxi Radical One", '-'),

       ('，', "Fullwidth Comma", ','),

       ('；', "Fullwidth Semicolon", ';'),
       ('︔', "Presentation Form For Vertical Semicolon", ';'),

       ('︓', "Presentation Form For Vertical Colon", ':'),

       ('︕', "Presentation Form For Vertical Exclamation Mark", '!'),

       ('？', "Fullwidth Question Mark", '?'),
       ('︖', "Presentation Form For Vertical Question Mark", '?'),

       ('·', "Middle Dot", '.'),
       ('・', "Katakana Middle Dot", '.'),
       ('･', "Halfwidth Katakana Middle Dot", '.'),
       ('᛫', "Runic Single Punctuation", '.'),
       ('·', "Greek Ano Teleia", '.'),
       ('⸱', "Word Separator Middle Dot", '.'),
       ('𐄁', "Aegean Word Separator Dot", '.'),
       ('•', "Bullet", '.'),
       ('‧', "Hyphenation Point", '.'),
       ('∙', "Bullet Operator", '.'),
       ('⋅', "Dot Operator", '.'),
       ('ꞏ', "Latin Letter Sinological Dot", '.'),
       ('ᐧ', "Canadian Syllabics Final Middle Dot", '.'),
       ('．', "Fullwidth Full Stop", '.'),
       ('。', "Ideographic Full Stop", '.'),
       ('︒', "Presentation Form For Vertical Ideographic Full Stop", '.'),


       ('˵', "Modifier Letter Middle Double Grave Accent", '"'),
       ('❞', "Heavy Double Comma Quotation Mark Ornament", '"'),
       ('❝', "Heavy Double Turned Comma Quotation Mark Ornament", '"'),

       ('（', "Fullwidth Left Parenthesis", '('),

       ('）', "Fullwidth Right Parenthesis", ')'),

       ('［', "Fullwidth Left Square Bracket", '['),
       ('❲', "Light Left Tortoise Shell Bracket Ornament", '['),
       ('「', "Left Corner Bracket", '['),
       ('『', "Left White Corner Bracket", '['),
       ('【', "Left Black Lenticular Bracket", '['),
       ('〔', "Left Tortoise Shell Bracket", '['),
       ('〖', "Left White Lenticular Bracket", '['),
       ('〘', "Left White Tortoise Shell Bracket", '['),
       ('〚', "Left White Square Bracket", '['),

       ('］', "Fullwidth Right Square Bracket", ']'),
       ('❳', "Light Right Tortoise Shell Bracket Ornament", ']'),
       ('」', "Right Corner Bracket", ']'),
       ('』', "Right White Corner Bracket", ']'),
       ('】', "Right Black Lenticular Bracket", ']'),
       ('〕', "Right Tortoise Shell Bracket", ']'),
       ('〗', "Right White Lenticular Bracket", ']'),
       ('〙', "Right White Tortoise Shell Bracket", ']'),
       ('〛', "Right White Square Bracket", ']'),

       ('｛', "Fullwidth Left Curly Bracket", '{'),

       ('｝', "Fullwidth Right Curly Bracket", '}'),

       ('＊', "Fullwidth Asterisk", '*'),

       ('／', "Fullwidth Solidus", '/'),

       ('、', "Ideographic Comma", '\\'),
       ('ヽ', "Katakana Iteration Mark", '\\'),

       ('＆', "Fullwidth Ampersand", '&'),

       ('﬩', "Hebrew Letter Alternative Plus Sign", '+'),
       ('＋', "Fullwidth Plus Sign", '+'),

       ('❬', "Medium Left-Pointing Angle Bracket Ornament", '<'),
       ('⟨', "Mathematical Left Angle Bracket", '<'),
       ('〈', "Left-Pointing Angle Bracket", '<'),
       ('〈', "Left Angle Bracket", '<'),
       ('㇛', "CJK Stroke Pd", '<'),
       ('く', "Hiragana Letter Ku", '<'),
       ('𡿨', "CJK Unified Ideograph-21FE8", '<'),
       ('《', "Left Double Angle Bracket", '<'),
       ('＜', "Fullwidth Less-Than Sign", '<'),

       ('＝', "Fullwidth Equals Sign", '='),

       ('❭', "Medium Right-Pointing Angle Bracket Ornament", '>'),
       ('⟩', "Mathematical Right Angle Bracket", '>'),
       ('〉', "Right-Pointing Angle Bracket", '>'),
       ('〉', "Right Angle Bracket", '>'),
       ('》', "Right Double Angle Bracket", '>'),
       ('＞', "Fullwidth Greater-Than Sign", '>'),
    ];

    for (fst, _, snd) in UNICODE_ARRAY2 {
        let fst_str = String::from_iter(Some(fst));
        let snd_str = String::from_iter(Some(snd));
        let fst_skeleton = skeleton(&fst_str).collect::<String>();
        let snd_skeleton = skeleton(&snd_str).collect::<String>();
        if fst_skeleton == snd_skeleton {
            println!("{:?} and {:?} pair is contained!", fst, snd);
        }
    }
}

