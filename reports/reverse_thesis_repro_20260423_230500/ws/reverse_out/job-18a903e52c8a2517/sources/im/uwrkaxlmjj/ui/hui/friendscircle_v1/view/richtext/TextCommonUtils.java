package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext;

import android.content.Context;
import android.net.Uri;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.StyleSpan;
import android.text.style.URLSpan;
import com.bjz.comm.net.bean.FCEntitysResponse;
import com.bjz.comm.net.bean.TopicBean;
import com.blankj.utilcode.constant.RegexConstants;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.LinkMovementClickMethod;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanUrlCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.LinkSpan;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes5.dex */
public class TextCommonUtils {
    public static final String urlPatternStr = "((http|ftp|https|rtsp)://)?(([a-zA-Z0-9\\._-]+\\.[a-zA-Z]{2,6})|([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}))(:[0-9]{1,4})?(/[a-zA-Z0-9\\&\\%_\\./-~-]*)?(\\?([一-龥0-9a-zA-Z\\&\\%\\.\\,_!~*'();?:@=+$#-]+\\=[一-龥0-9a-zA-Z\\&\\%\\.\\,_!~*'();?:@=+$#-]+\\&?)+)?";

    public static void setEmojiText(Context context, String text, ITextViewShow tv) {
        if (TextUtils.isEmpty(text)) {
            tv.setText("");
        }
        Spannable spannable = SmileUtils.unicodeToEmojiName(context, text);
        tv.setText(spannable);
    }

    public static Spannable getEmojiText(Context context, String text, int size) {
        return getEmojiText(context, text, size, 0);
    }

    public static Spannable getEmojiText(Context context, String text, int size, int verticalAlignment) {
        if (TextUtils.isEmpty(text)) {
            return new SpannableString("");
        }
        return SmileUtils.unicodeToEmojiName(context, text, size, verticalAlignment);
    }

    public static Spannable getEmojiText(Context context, String text) {
        return getEmojiText(context, text, -1);
    }

    public static Spannable getUrlEmojiText(Context context, String text, ITextViewShow textView, int color, boolean needNum, SpanAtUserCallBack spanAtUserCallBack, SpanUrlCallBack spanUrlCallBack) {
        if (!TextUtils.isEmpty(text)) {
            return getUrlSmileText(context, text, null, textView, color, 0, needNum, spanAtUserCallBack, spanUrlCallBack);
        }
        return new SpannableString(" ");
    }

    public static void setUrlSmileText(Context context, String string, List<FCEntitysResponse> listUser, ITextViewShow textView, int color, boolean needNum, SpanAtUserCallBack spanAtUserCallBack, SpanUrlCallBack spanUrlCallBack) {
        Spannable spannable = getUrlSmileText(context, string, listUser, textView, color, 0, needNum, spanAtUserCallBack, spanUrlCallBack);
        textView.setText(spannable);
    }

    public static Spannable getAtText(Context context, List<FCEntitysResponse> listUser, List<TopicBean> listTopic, String content, ITextViewShow textView, boolean clickable, int color, int topicColor, SpanAtUserCallBack spanAtUserCallBack, SpanTopicCallBack spanTopicCallBack) {
        int lenght;
        boolean hadHighLine;
        Spannable spannable = null;
        if (listTopic != null && listTopic.size() > 0) {
            spannable = getTopicText(context, listTopic, content, textView, clickable, topicColor, spanTopicCallBack);
        }
        if ((listUser == null || listUser.size() <= 0) && spannable == null) {
            return getEmojiText(context, content, textView.emojiSize());
        }
        Spannable spannableString = new SpannableString(spannable == null ? content : spannable);
        int lenght2 = content.length();
        boolean hadHighLine2 = false;
        int i = 0;
        while (i < listUser.size()) {
            FCEntitysResponse fcEntitysResponse = listUser.get(i);
            if (fcEntitysResponse == null) {
                lenght = lenght2;
            } else {
                String userName = fcEntitysResponse.getUserName();
                int start = fcEntitysResponse.getUOffset();
                int end = fcEntitysResponse.getULimit() + start;
                if (start < 0 || end <= start || end > lenght2) {
                    lenght = lenght2;
                } else if (!TextUtils.equals(content.substring(start, end), userName)) {
                    lenght = lenght2;
                } else {
                    ClickAtUserSpan clickAtUserSpan = null;
                    if (textView != null) {
                        lenght = lenght2;
                        clickAtUserSpan = textView.getCustomClickAtUserSpan(context, listUser.get(i), color, spanAtUserCallBack);
                    } else {
                        lenght = lenght2;
                    }
                    if (clickAtUserSpan == null) {
                        hadHighLine = true;
                        clickAtUserSpan = new ClickAtUserSpan(listUser.get(i), color, spanAtUserCallBack);
                    } else {
                        hadHighLine = true;
                    }
                    spannableString.setSpan(clickAtUserSpan, start, end, 18);
                    hadHighLine2 = hadHighLine;
                }
            }
            i++;
            lenght2 = lenght;
        }
        int lenght3 = textView.emojiSize();
        SmileUtils.addSmiles(context, lenght3, textView.verticalAlignment(), spannableString);
        if (clickable && hadHighLine2) {
            textView.setMovementMethod(LinkMovementClickMethod.getInstance());
        }
        return spannableString;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x00a3 A[PHI: r11
      0x00a3: PHI (r11v5 'index' int) = (r11v4 'index' int), (r11v4 'index' int), (r11v6 'index' int), (r11v6 'index' int) binds: [B:11:0x0053, B:12:0x0055, B:14:0x0078, B:18:0x0098] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.text.Spannable getTopicText(android.content.Context r20, java.util.List<com.bjz.comm.net.bean.TopicBean> r21, java.lang.String r22, im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow r23, boolean r24, int r25, im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack r26) {
        /*
            Method dump skipped, instruction units count: 365
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.richtext.TextCommonUtils.getTopicText(android.content.Context, java.util.List, java.lang.String, im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.ITextViewShow, boolean, int, im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanTopicCallBack):android.text.Spannable");
    }

    public static Spannable getUrlSmileText(Context context, String string, List<FCEntitysResponse> listUser, ITextViewShow textView, int colorAt, int colorLink, boolean needNum, SpanAtUserCallBack spanAtUserCallBack, SpanUrlCallBack spanUrlCallBack) {
        return getAllSpanText(context, string, listUser, null, textView, colorAt, colorLink, 0, needNum, true, spanAtUserCallBack, spanUrlCallBack, null);
    }

    public static Spannable getAllSpanText(Context context, String string, List<FCEntitysResponse> listUser, List<TopicBean> listTopic, ITextViewShow textView, int colorAt, int colorLink, int colorTopic, boolean needNum, boolean needUrl, SpanAtUserCallBack spanAtUserCallBack, SpanUrlCallBack spanUrlCallBack, SpanTopicCallBack spanTopicCallBack) {
        if (needUrl || needNum) {
            textView.setAutoLinkMask(7);
        }
        if (!TextUtils.isEmpty(string)) {
            Spannable spannable = getAtText(context, listUser, listTopic, string, textView, true, colorAt, colorTopic, spanAtUserCallBack, spanTopicCallBack);
            textView.setText(spannable);
            if (needUrl || needNum) {
                return resolveUrlLogic(context, textView, spannable, listUser, colorLink, needNum, needUrl, spanUrlCallBack);
            }
            return spannable;
        }
        return new SpannableString(" ");
    }

    private static Spannable resolveUrlLogic(Context context, ITextViewShow textView, Spannable spannable, List<FCEntitysResponse> listUser, int color, boolean needNum, boolean needUrl, SpanUrlCallBack spanUrlCallBack) {
        CharSequence charSequence;
        Iterator<FCEntitysResponse> it;
        URLSpan[] urls;
        CharSequence charSequence2 = textView.getText();
        if (charSequence2 instanceof Spannable) {
            int end = charSequence2.length();
            Spannable sp = (Spannable) textView.getText();
            URLSpan[] urls2 = (URLSpan[]) sp.getSpans(0, end, URLSpan.class);
            ClickAtUserSpan[] atSpan = (ClickAtUserSpan[]) sp.getSpans(0, end, ClickAtUserSpan.class);
            if (!TextUtils.isEmpty(charSequence2)) {
                SpannableStringBuilder style = new SpannableStringBuilder(charSequence2);
                style.clearSpans();
                if (urls2.length > 0) {
                    if (needNum) {
                        int length = urls2.length;
                        int i = 0;
                        while (i < length) {
                            URLSpan url = urls2[i];
                            String urlString = url.getURL();
                            FileLog.e("urlString == " + urlString);
                            int end2 = end;
                            if (isNumeric(urlString.replace("tel:", "")) && isMobileSimple(urlString.replace("tel:", ""))) {
                                LinkSpan linkSpan = null;
                                if (textView != null) {
                                    linkSpan = textView.getCustomLinkSpan(context, url.getURL(), color, spanUrlCallBack);
                                }
                                if (linkSpan == null) {
                                    linkSpan = new LinkSpan(url.getURL(), color, spanUrlCallBack);
                                }
                                urls = urls2;
                                style.setSpan(linkSpan, sp.getSpanStart(url), sp.getSpanEnd(url), 33);
                            } else {
                                urls = urls2;
                                style.setSpan(new StyleSpan(0), sp.getSpanStart(url), sp.getSpanEnd(url), 34);
                            }
                            i++;
                            end = end2;
                            urls2 = urls;
                        }
                    }
                    if (needUrl) {
                        Pattern pattern = Pattern.compile("((http|ftp|https|rtsp)://)?(([a-zA-Z0-9\\._-]+\\.[a-zA-Z]{2,6})|([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}))(:[0-9]{1,4})?(/[a-zA-Z0-9\\&\\%_\\./-~-]*)?(\\?([一-龥0-9a-zA-Z\\&\\%\\.\\,_!~*'();?:@=+$#-]+\\=[一-龥0-9a-zA-Z\\&\\%\\.\\,_!~*'();?:@=+$#-]+\\&?)+)?", 2);
                        Matcher matcher = pattern.matcher(charSequence2);
                        while (matcher.find()) {
                            int urlStart = matcher.start();
                            int urlEnd = matcher.end();
                            String url2 = matcher.group();
                            FileLog.e("urlString == " + url2);
                            Uri parse = Uri.parse(url2);
                            StringBuilder sb = new StringBuilder();
                            Pattern pattern2 = pattern;
                            sb.append("urlString parse== ");
                            sb.append(parse.getHost());
                            FileLog.e(sb.toString());
                            LinkSpan linkSpan2 = textView.getCustomLinkSpan(context, url2, color, spanUrlCallBack);
                            if (linkSpan2 == null) {
                                linkSpan2 = new LinkSpan(url2, color, spanUrlCallBack);
                            }
                            style.setSpan(linkSpan2, urlStart, urlEnd, 33);
                            pattern = pattern2;
                        }
                    }
                } else if (needUrl && listUser != null) {
                    Iterator<FCEntitysResponse> it2 = listUser.iterator();
                    while (it2.hasNext()) {
                        FCEntitysResponse bean = it2.next();
                        int type = bean.getType();
                        int offset = bean.getUOffset();
                        int limit = bean.getULimit();
                        if (offset < 0 || limit <= 0 || offset + limit > charSequence2.length()) {
                            charSequence = charSequence2;
                            it = it2;
                        } else if (type == 2) {
                            LinkSpan linkSpan3 = null;
                            String subUrl = charSequence2.toString().substring(offset, offset + limit);
                            URLSpan urlSpan = new URLSpan(subUrl);
                            if (textView == null) {
                                charSequence = charSequence2;
                            } else {
                                charSequence = charSequence2;
                                linkSpan3 = textView.getCustomLinkSpan(context, urlSpan.getURL(), color, spanUrlCallBack);
                            }
                            if (linkSpan3 != null) {
                                it = it2;
                            } else {
                                it = it2;
                                linkSpan3 = new LinkSpan(urlSpan.getURL(), color, spanUrlCallBack);
                            }
                            style.setSpan(linkSpan3, offset, offset + limit, 33);
                        } else {
                            charSequence = charSequence2;
                            it = it2;
                            style.setSpan(new StyleSpan(0), offset, offset + limit, 34);
                        }
                        charSequence2 = charSequence;
                        it2 = it;
                    }
                }
                for (ClickAtUserSpan atUserSpan : atSpan) {
                    LinkSpan[] removeUrls = (LinkSpan[]) style.getSpans(sp.getSpanStart(atUserSpan), sp.getSpanEnd(atUserSpan), LinkSpan.class);
                    if (removeUrls != null && removeUrls.length > 0) {
                        for (LinkSpan linkSpan4 : removeUrls) {
                            style.removeSpan(linkSpan4);
                        }
                    }
                    style.setSpan(atUserSpan, sp.getSpanStart(atUserSpan), sp.getSpanEnd(atUserSpan), 18);
                }
                SmileUtils.addSmiles(context, textView.emojiSize(), textView.verticalAlignment(), style);
                textView.setAutoLinkMask(0);
                return style;
            }
            textView.setAutoLinkMask(0);
            return spannable;
        }
        textView.setAutoLinkMask(0);
        return spannable;
    }

    private static boolean isTopURL(String str) {
        String[] ss = str.split("\\.");
        if (ss.length < 2) {
            return false;
        }
        return true;
    }

    private static boolean isNumeric(String str) {
        Pattern pattern = Pattern.compile("[0-9]*");
        Matcher isNum = pattern.matcher(str);
        if (!isNum.matches()) {
            return false;
        }
        return true;
    }

    private static boolean isMobileSimple(String string) {
        return !TextUtils.isEmpty(string) && Pattern.matches(RegexConstants.REGEX_MOBILE_SIMPLE, string);
    }
}
