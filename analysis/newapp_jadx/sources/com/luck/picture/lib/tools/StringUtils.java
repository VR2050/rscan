package com.luck.picture.lib.tools;

import android.annotation.SuppressLint;
import android.content.Context;
import android.text.SpannableString;
import android.text.style.RelativeSizeSpan;
import android.widget.TextView;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.config.PictureMimeType;
import java.util.regex.Pattern;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class StringUtils {
    public static String getEncryptionValue(String str, int i2, int i3) {
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append("_");
        sb.append(i2);
        sb.append("x");
        sb.append(i3);
        return ValueOf.toString(Integer.valueOf(Math.abs(hash(Integer.valueOf(sb.hashCode())))));
    }

    @SuppressLint({"StringFormatMatches"})
    public static String getMsg(Context context, String str, int i2) {
        return PictureMimeType.isHasVideo(str) ? context.getString(C3979R.string.picture_message_video_max_num, Integer.valueOf(i2)) : PictureMimeType.isHasAudio(str) ? context.getString(C3979R.string.picture_message_audio_max_num, Integer.valueOf(i2)) : context.getString(C3979R.string.picture_message_max_num, Integer.valueOf(i2));
    }

    public static final int hash(Object obj) {
        if (obj == null) {
            return 0;
        }
        int hashCode = obj.hashCode();
        return hashCode ^ (hashCode >>> 16);
    }

    public static String rename(String str) {
        String substring = str.substring(0, str.lastIndexOf("."));
        String substring2 = str.substring(str.lastIndexOf("."));
        StringBuilder m590L = C1499a.m590L(substring, "_");
        m590L.append(DateUtils.getCreateFileName());
        m590L.append(substring2);
        return m590L.toString();
    }

    public static String renameSuffix(String str, String str2) {
        return C1499a.m637w(str.substring(0, str.lastIndexOf(".")), str2);
    }

    public static int stringToInt(String str) {
        if (Pattern.compile("^[-\\+]?[\\d]+$").matcher(str).matches()) {
            return Integer.valueOf(str).intValue();
        }
        return 0;
    }

    public static void tempTextFont(TextView textView, int i2) {
        String trim = textView.getText().toString().trim();
        String string = i2 == PictureMimeType.ofAudio() ? textView.getContext().getString(C3979R.string.picture_empty_audio_title) : textView.getContext().getString(C3979R.string.picture_empty_title);
        String m637w = C1499a.m637w(string, trim);
        SpannableString spannableString = new SpannableString(m637w);
        spannableString.setSpan(new RelativeSizeSpan(0.8f), string.length(), m637w.length(), 33);
        textView.setText(spannableString);
    }
}
