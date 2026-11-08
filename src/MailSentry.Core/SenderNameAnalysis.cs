using System.Globalization;
using System.Text;

namespace MailSentry;

public static class SenderNameAnalysis
{
    // A deliberately limited set of Latin lookalikes, applied
    // only by explicit sender-name operators. This is not a full UTS #39 skeleton.
    // Accents and other scripts are preserved; international names are not spam.
    public static string Skeleton(string value)
    {
        // Preserve case until after mapping: Greek capital Nu resembles N,
        // whereas Greek small nu resembles v. NFKC handles styled/fullwidth text.
        var text = value.Normalize(NormalizationForm.FormKC);
        var result = new StringBuilder(text.Length);
        foreach (var rune in text.EnumerateRunes())
        {
            if (Rune.GetUnicodeCategory(rune) == UnicodeCategory.Format) continue;
            result.Append(rune.Value switch
            {
                0x0391 or 0x0410 => "a",
                0x0392 or 0x0412 => "b",
                0x0421 or 0x03F9 => "c",
                0x0395 or 0x0415 => "e",
                0x0397 or 0x041D => "h",
                0x0399 or 0x0406 => "i",
                0x0408 => "j",
                0x039A or 0x041A => "k",
                0x039C or 0x041C => "m",
                0x039D => "n",
                0x039F or 0x041E => "o",
                0x03A1 or 0x0420 => "p",
                0x0405 => "s",
                0x03A4 or 0x0422 => "t",
                0x03A5 => "y",
                0x03A7 or 0x0425 => "x",
                0x0396 => "z",
                0x0430 or 0x03B1 => "a", // Cyrillic а, Greek α
                0x0432 or 0x03B2 => "b",
                0x0441 or 0x03F2 => "c",
                0x0501 => "d",
                0x0435 or 0x03B5 => "e",
                0x04BB => "h",
                0x0456 or 0x03B9 => "i",
                0x0458 => "j",
                0x043A or 0x03BA => "k",
                0x04CF => "l",
                0x043C => "m",
                0x0578 => "n", // Armenian ո
                0x043E or 0x03BF => "o",
                0x0440 or 0x03C1 => "p",
                0x051B => "q",
                0x0455 => "s",
                0x0442 or 0x03C4 => "t",
                0x03C5 => "u",
                0x03BD => "v",
                0x051D => "w",
                0x0445 or 0x03C7 => "x",
                0x0443 => "y",
                0x03B6 => "z",
                _ => rune.ToString()
            });
        }
        return SignatureFormat.Normalize(result.ToString());
    }

    private static string CanonicalText(string value) => value.Normalize(NormalizationForm.FormC).Trim().ToLowerInvariant();

    public static bool HasConfusables(string value) => Skeleton(value) != CanonicalText(value);

    public static bool Matches(string senderName, string brand, bool contains)
    {
        // Retain compatibility lettering in this comparison so fullwidth and
        // mathematical alphabets are also recognised as obfuscated branding.
        var original = CanonicalText(senderName);
        var target = SignatureFormat.Normalize(brand);
        var skeleton = Skeleton(senderName);
        // Require actual obfuscation of the target, not merely another script
        // elsewhere in an otherwise ordinary brand display name.
        return contains
            ? !original.Contains(target, StringComparison.Ordinal) && skeleton.Contains(target, StringComparison.Ordinal)
            : original != target && skeleton == target;
    }
}
