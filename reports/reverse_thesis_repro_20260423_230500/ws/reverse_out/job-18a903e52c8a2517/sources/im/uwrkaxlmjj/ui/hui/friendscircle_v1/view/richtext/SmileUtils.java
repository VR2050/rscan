package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.style.CharacterStyle;
import android.text.style.ForegroundColorSpan;
import android.widget.EditText;
import com.king.zxing.util.LogUtils;
import com.litesuits.orm.db.assit.SQLBuilder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.CenteredImageSpan;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class SmileUtils {
    private static final Spannable.Factory spannableFactory = Spannable.Factory.getInstance();
    private static final Map<Pattern, Integer> emoticons = new HashMap();
    private static final List<String> textList = new ArrayList();
    public static String[] specials = {"\\", "\\/", "*", ".", "?", Marker.ANY_NON_NULL_MARKER, "$", "^", "[", "]", SQLBuilder.PARENTHESES_LEFT, SQLBuilder.PARENTHESES_RIGHT, "{", "}", LogUtils.VERTICAL};

    public Map<Pattern, Integer> getEmotions() {
        return emoticons;
    }

    private static void addPattern(Map<Pattern, Integer> map, String smile, int resource) {
        map.put(Pattern.compile(Pattern.quote(smile)), Integer.valueOf(resource));
    }

    public static void addPatternAll(Map<Pattern, Integer> map, List<String> smile, List<Integer> resource) {
        map.clear();
        textList.clear();
        if (smile.size() != resource.size()) {
            try {
                throw new Exception("**********文本与图片list不相等");
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            textList.addAll(smile);
            for (int i = 0; i < smile.size(); i++) {
                map.put(Pattern.compile(Pattern.quote(smile.get(i))), resource.get(i));
            }
        }
    }

    public static int getRedId(String string) {
        for (Map.Entry<Pattern, Integer> entry : emoticons.entrySet()) {
            Matcher matcher = entry.getKey().matcher(string);
            if (matcher.find()) {
                return entry.getValue().intValue();
            }
        }
        return -1;
    }

    public static void insertIcon(EditText editText, int maxLength, int size, String name) {
        String curString = editText.toString();
        if (curString.length() + name.length() > maxLength) {
            return;
        }
        int resId = getRedId(name);
        Drawable drawable = editText.getResources().getDrawable(resId);
        if (drawable == null) {
            return;
        }
        drawable.setBounds(0, 0, size, size);
        CenteredImageSpan CenteredImageSpan = new CenteredImageSpan(drawable);
        SpannableString spannableString = new SpannableString(name);
        spannableString.setSpan(CenteredImageSpan, 0, spannableString.length(), 33);
        int index = Math.max(editText.getSelectionStart(), 0);
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(editText.getText());
        spannableStringBuilder.insert(index, (CharSequence) spannableString);
        editText.setText(spannableStringBuilder);
        editText.setSelection(spannableString.length() + index);
    }

    public static boolean addSmiles(Context context, Spannable spannable) {
        return addSmiles(context, -1, spannable);
    }

    public static boolean addSmiles(Context context, int size, Spannable spannable) {
        return addSmiles(context, size, 0, spannable);
    }

    public static boolean addSmiles(Context context, int size, int verticalAlignment, Spannable spannable) {
        boolean hasChanges = false;
        for (Map.Entry<Pattern, Integer> entry : emoticons.entrySet()) {
            Matcher matcher = entry.getKey().matcher(spannable);
            while (matcher.find()) {
                boolean set = true;
                for (CenteredImageSpan span : (CenteredImageSpan[]) spannable.getSpans(matcher.start(), matcher.end(), CenteredImageSpan.class)) {
                    if (spannable.getSpanStart(span) >= matcher.start() && spannable.getSpanEnd(span) <= matcher.end()) {
                        spannable.removeSpan(span);
                    } else {
                        set = false;
                        break;
                    }
                }
                if (set) {
                    hasChanges = true;
                    if (size <= 0) {
                        spannable.setSpan(new CenteredImageSpan(context, entry.getValue().intValue(), verticalAlignment), matcher.start(), matcher.end(), 33);
                    } else {
                        Drawable drawable = context.getResources().getDrawable(entry.getValue().intValue());
                        if (drawable != null) {
                            drawable.setBounds(0, 0, size, size);
                            CenteredImageSpan CenteredImageSpan = new CenteredImageSpan(drawable, verticalAlignment);
                            spannable.setSpan(CenteredImageSpan, matcher.start(), matcher.end(), 33);
                        }
                    }
                }
            }
        }
        return hasChanges;
    }

    public static Spannable getSmiledText(Context context, CharSequence text) {
        return getSmiledText(context, text, -1);
    }

    public static Spannable getSmiledText(Context context, CharSequence text, int size) {
        return getSmiledText(context, text, size, 0);
    }

    public static Spannable getSmiledText(Context context, CharSequence text, int size, int verticalAlignment) {
        Spannable spannable = spannableFactory.newSpannable(text);
        addSmiles(context, size, verticalAlignment, spannable);
        return spannable;
    }

    public static boolean containsKey(String key) {
        for (Map.Entry<Pattern, Integer> entry : emoticons.entrySet()) {
            Matcher matcher = entry.getKey().matcher(key);
            if (matcher.find()) {
                return true;
            }
        }
        return false;
    }

    public static Map<Pattern, Integer> getEmoticons() {
        return emoticons;
    }

    public static String stringToUnicode(String string) {
        StringBuffer unicode = new StringBuffer();
        for (int i = 0; i < string.length(); i++) {
            char c = string.charAt(i);
            unicode.append("\\u" + String.format("%04", Integer.toHexString(c)));
        }
        return "[" + unicode.toString() + "]";
    }

    public static String unicode2String(String unicode) {
        StringBuffer string = new StringBuffer();
        String[] hex = unicode.split("\\\\u");
        for (int i = 1; i < hex.length; i++) {
            int data = Integer.parseInt(hex[i], 16);
            string.append((char) data);
        }
        return string.toString();
    }

    public static SpannableStringBuilder highlight(String text, String target) {
        SpannableStringBuilder spannable = new SpannableStringBuilder(text);
        int i = 0;
        while (true) {
            String[] strArr = specials;
            if (i >= strArr.length) {
                break;
            }
            if (target.contains(strArr[i])) {
                target = target.replace(specials[i], "\\" + specials[i]);
            }
            i++;
        }
        Pattern p = Pattern.compile(target.toLowerCase());
        Matcher m = p.matcher(text.toLowerCase());
        while (m.find()) {
            CharacterStyle span = new ForegroundColorSpan(Color.rgb(253, 113, 34));
            spannable.setSpan(span, m.start(), m.end(), 33);
        }
        return spannable;
    }

    public static SpannableStringBuilder highlight(Spannable text, String target) {
        SpannableStringBuilder spannable = new SpannableStringBuilder(text);
        Pattern p = Pattern.compile(target);
        Matcher m = p.matcher(text);
        while (m.find()) {
            CharacterStyle span = new ForegroundColorSpan(Color.rgb(253, 113, 34));
            spannable.setSpan(span, m.start(), m.end(), 33);
        }
        return spannable;
    }

    public static SpannableStringBuilder highlight(String text) {
        SpannableStringBuilder spannable = new SpannableStringBuilder(text);
        CharacterStyle span = new ForegroundColorSpan(Color.rgb(253, 113, 34));
        spannable.setSpan(span, 0, text.length(), 33);
        return spannable;
    }

    public static Spannable unicodeToEmojiName(Context context, String content, int size, int verticalAlignment) {
        Spannable spannable = getSmiledText(context, content, size, verticalAlignment);
        return spannable;
    }

    public static Spannable unicodeToEmojiName(Context context, String content, int size) {
        Spannable spannable = getSmiledText(context, content, size);
        return spannable;
    }

    public static Spannable unicodeToEmojiName(Context context, String content) {
        Spannable spannable = getSmiledText(context, content, -1);
        return spannable;
    }

    public static List<String> getTextList() {
        return textList;
    }
}
