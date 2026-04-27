package com.google.android.exoplayer2.text.webvtt;

import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.AlignmentSpan;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StrikethroughSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;
import android.text.style.UnderlineSpan;
import com.google.android.exoplayer2.text.webvtt.WebvttCue;
import com.google.android.exoplayer2.util.Log;
import com.google.android.exoplayer2.util.ParsableByteArray;
import com.google.android.exoplayer2.util.Util;
import com.king.zxing.util.LogUtils;
import com.snail.antifake.deviceid.ShellAdbUtils;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes2.dex */
public final class WebvttCueParser {
    private static final char CHAR_AMPERSAND = '&';
    private static final char CHAR_GREATER_THAN = '>';
    private static final char CHAR_LESS_THAN = '<';
    private static final char CHAR_SEMI_COLON = ';';
    private static final char CHAR_SLASH = '/';
    private static final char CHAR_SPACE = ' ';
    public static final Pattern CUE_HEADER_PATTERN = Pattern.compile("^(\\S+)\\s+-->\\s+(\\S+)(.*)?$");
    private static final Pattern CUE_SETTING_PATTERN = Pattern.compile("(\\S+?):(\\S+)");
    private static final String ENTITY_AMPERSAND = "amp";
    private static final String ENTITY_GREATER_THAN = "gt";
    private static final String ENTITY_LESS_THAN = "lt";
    private static final String ENTITY_NON_BREAK_SPACE = "nbsp";
    private static final int STYLE_BOLD = 1;
    private static final int STYLE_ITALIC = 2;
    private static final String TAG = "WebvttCueParser";
    private static final String TAG_BOLD = "b";
    private static final String TAG_CLASS = "c";
    private static final String TAG_ITALIC = "i";
    private static final String TAG_LANG = "lang";
    private static final String TAG_UNDERLINE = "u";
    private static final String TAG_VOICE = "v";
    private final StringBuilder textBuilder = new StringBuilder();

    public boolean parseCue(ParsableByteArray webvttData, WebvttCue.Builder builder, List<WebvttCssStyle> styles) {
        String firstLine = webvttData.readLine();
        if (firstLine == null) {
            return false;
        }
        Matcher cueHeaderMatcher = CUE_HEADER_PATTERN.matcher(firstLine);
        if (cueHeaderMatcher.matches()) {
            return parseCue(null, cueHeaderMatcher, webvttData, builder, this.textBuilder, styles);
        }
        String secondLine = webvttData.readLine();
        if (secondLine == null) {
            return false;
        }
        Matcher cueHeaderMatcher2 = CUE_HEADER_PATTERN.matcher(secondLine);
        if (!cueHeaderMatcher2.matches()) {
            return false;
        }
        return parseCue(firstLine.trim(), cueHeaderMatcher2, webvttData, builder, this.textBuilder, styles);
    }

    static void parseCueSettingsList(String cueSettingsList, WebvttCue.Builder builder) {
        Matcher cueSettingMatcher = CUE_SETTING_PATTERN.matcher(cueSettingsList);
        while (cueSettingMatcher.find()) {
            String name = cueSettingMatcher.group(1);
            String value = cueSettingMatcher.group(2);
            try {
                if ("line".equals(name)) {
                    parseLineAttribute(value, builder);
                } else if ("align".equals(name)) {
                    builder.setTextAlignment(parseTextAlignment(value));
                } else if ("position".equals(name)) {
                    parsePositionAttribute(value, builder);
                } else if ("size".equals(name)) {
                    builder.setWidth(WebvttParserUtil.parsePercentage(value));
                } else {
                    Log.w(TAG, "Unknown cue setting " + name + LogUtils.COLON + value);
                }
            } catch (NumberFormatException e) {
                Log.w(TAG, "Skipping bad cue setting: " + cueSettingMatcher.group());
            }
        }
    }

    static void parseCueText(String id, String markup, WebvttCue.Builder builder, List<WebvttCssStyle> styles) {
        int entityEndIndex;
        SpannableStringBuilder spannedText = new SpannableStringBuilder();
        ArrayDeque<StartTag> startTagStack = new ArrayDeque<>();
        List<StyleMatch> scratchStyleMatches = new ArrayList<>();
        int pos = 0;
        while (pos < markup.length()) {
            char curr = markup.charAt(pos);
            if (curr == '&') {
                int semiColonEndIndex = markup.indexOf(59, pos + 1);
                int spaceEndIndex = markup.indexOf(32, pos + 1);
                if (semiColonEndIndex == -1) {
                    entityEndIndex = spaceEndIndex;
                } else {
                    entityEndIndex = spaceEndIndex == -1 ? semiColonEndIndex : Math.min(semiColonEndIndex, spaceEndIndex);
                }
                if (entityEndIndex != -1) {
                    applyEntity(markup.substring(pos + 1, entityEndIndex), spannedText);
                    if (entityEndIndex == spaceEndIndex) {
                        spannedText.append(" ");
                    }
                    pos = entityEndIndex + 1;
                } else {
                    spannedText.append(curr);
                    pos++;
                }
            } else if (curr == '<') {
                if (pos + 1 >= markup.length()) {
                    pos++;
                } else {
                    int ltPos = pos;
                    boolean isClosingTag = markup.charAt(ltPos + 1) == '/';
                    pos = findEndOfTag(markup, ltPos + 1);
                    boolean isVoidTag = markup.charAt(pos + (-2)) == '/';
                    String fullTagExpression = markup.substring((isClosingTag ? 2 : 1) + ltPos, isVoidTag ? pos - 2 : pos - 1);
                    String tagName = getTagName(fullTagExpression);
                    if (tagName != null && isSupportedTag(tagName)) {
                        if (isClosingTag) {
                            while (!startTagStack.isEmpty()) {
                                StartTag startTag = startTagStack.pop();
                                applySpansForTag(id, startTag, spannedText, styles, scratchStyleMatches);
                                if (startTag.name.equals(tagName)) {
                                    break;
                                }
                            }
                        } else if (!isVoidTag) {
                            startTagStack.push(StartTag.buildStartTag(fullTagExpression, spannedText.length()));
                        }
                    }
                }
            } else {
                spannedText.append(curr);
                pos++;
            }
        }
        while (!startTagStack.isEmpty()) {
            applySpansForTag(id, startTagStack.pop(), spannedText, styles, scratchStyleMatches);
        }
        applySpansForTag(id, StartTag.buildWholeCueVirtualTag(), spannedText, styles, scratchStyleMatches);
        builder.setText(spannedText);
    }

    private static boolean parseCue(String id, Matcher cueHeaderMatcher, ParsableByteArray webvttData, WebvttCue.Builder builder, StringBuilder textBuilder, List<WebvttCssStyle> styles) {
        try {
            builder.setStartTime(WebvttParserUtil.parseTimestampUs(cueHeaderMatcher.group(1))).setEndTime(WebvttParserUtil.parseTimestampUs(cueHeaderMatcher.group(2)));
            parseCueSettingsList(cueHeaderMatcher.group(3), builder);
            textBuilder.setLength(0);
            while (true) {
                String line = webvttData.readLine();
                if (!TextUtils.isEmpty(line)) {
                    if (textBuilder.length() > 0) {
                        textBuilder.append(ShellAdbUtils.COMMAND_LINE_END);
                    }
                    textBuilder.append(line.trim());
                } else {
                    parseCueText(id, textBuilder.toString(), builder, styles);
                    return true;
                }
            }
        } catch (NumberFormatException e) {
            Log.w(TAG, "Skipping cue with bad header: " + cueHeaderMatcher.group());
            return false;
        }
    }

    private static void parseLineAttribute(String s, WebvttCue.Builder builder) throws NumberFormatException {
        int commaIndex = s.indexOf(44);
        if (commaIndex != -1) {
            builder.setLineAnchor(parsePositionAnchor(s.substring(commaIndex + 1)));
            s = s.substring(0, commaIndex);
        } else {
            builder.setLineAnchor(Integer.MIN_VALUE);
        }
        if (s.endsWith("%")) {
            builder.setLine(WebvttParserUtil.parsePercentage(s)).setLineType(0);
            return;
        }
        int lineNumber = Integer.parseInt(s);
        if (lineNumber < 0) {
            lineNumber--;
        }
        builder.setLine(lineNumber).setLineType(1);
    }

    private static void parsePositionAttribute(String s, WebvttCue.Builder builder) throws NumberFormatException {
        int commaIndex = s.indexOf(44);
        if (commaIndex != -1) {
            builder.setPositionAnchor(parsePositionAnchor(s.substring(commaIndex + 1)));
            s = s.substring(0, commaIndex);
        } else {
            builder.setPositionAnchor(Integer.MIN_VALUE);
        }
        builder.setPosition(WebvttParserUtil.parsePercentage(s));
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0034  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static int parsePositionAnchor(java.lang.String r5) {
        /*
            int r0 = r5.hashCode()
            r1 = 0
            r2 = 3
            r3 = 2
            r4 = 1
            switch(r0) {
                case -1364013995: goto L2a;
                case -1074341483: goto L20;
                case 100571: goto L16;
                case 109757538: goto Lc;
                default: goto Lb;
            }
        Lb:
            goto L34
        Lc:
            java.lang.String r0 = "start"
            boolean r0 = r5.equals(r0)
            if (r0 == 0) goto Lb
            r0 = 0
            goto L35
        L16:
            java.lang.String r0 = "end"
            boolean r0 = r5.equals(r0)
            if (r0 == 0) goto Lb
            r0 = 3
            goto L35
        L20:
            java.lang.String r0 = "middle"
            boolean r0 = r5.equals(r0)
            if (r0 == 0) goto Lb
            r0 = 2
            goto L35
        L2a:
            java.lang.String r0 = "center"
            boolean r0 = r5.equals(r0)
            if (r0 == 0) goto Lb
            r0 = 1
            goto L35
        L34:
            r0 = -1
        L35:
            if (r0 == 0) goto L58
            if (r0 == r4) goto L57
            if (r0 == r3) goto L57
            if (r0 == r2) goto L56
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "Invalid anchor value: "
            r0.append(r1)
            r0.append(r5)
            java.lang.String r0 = r0.toString()
            java.lang.String r1 = "WebvttCueParser"
            com.google.android.exoplayer2.util.Log.w(r1, r0)
            r0 = -2147483648(0xffffffff80000000, float:-0.0)
            return r0
        L56:
            return r3
        L57:
            return r4
        L58:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.text.webvtt.WebvttCueParser.parsePositionAnchor(java.lang.String):int");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0049  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static android.text.Layout.Alignment parseTextAlignment(java.lang.String r6) {
        /*
            int r0 = r6.hashCode()
            r1 = 5
            r2 = 4
            r3 = 3
            r4 = 2
            r5 = 1
            switch(r0) {
                case -1364013995: goto L3f;
                case -1074341483: goto L35;
                case 100571: goto L2b;
                case 3317767: goto L21;
                case 108511772: goto L17;
                case 109757538: goto Ld;
                default: goto Lc;
            }
        Lc:
            goto L49
        Ld:
            java.lang.String r0 = "start"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lc
            r0 = 0
            goto L4a
        L17:
            java.lang.String r0 = "right"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lc
            r0 = 5
            goto L4a
        L21:
            java.lang.String r0 = "left"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lc
            r0 = 1
            goto L4a
        L2b:
            java.lang.String r0 = "end"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lc
            r0 = 4
            goto L4a
        L35:
            java.lang.String r0 = "middle"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lc
            r0 = 3
            goto L4a
        L3f:
            java.lang.String r0 = "center"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lc
            r0 = 2
            goto L4a
        L49:
            r0 = -1
        L4a:
            if (r0 == 0) goto L74
            if (r0 == r5) goto L74
            if (r0 == r4) goto L71
            if (r0 == r3) goto L71
            if (r0 == r2) goto L6e
            if (r0 == r1) goto L6e
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "Invalid alignment value: "
            r0.append(r1)
            r0.append(r6)
            java.lang.String r0 = r0.toString()
            java.lang.String r1 = "WebvttCueParser"
            com.google.android.exoplayer2.util.Log.w(r1, r0)
            r0 = 0
            return r0
        L6e:
            android.text.Layout$Alignment r0 = android.text.Layout.Alignment.ALIGN_OPPOSITE
            return r0
        L71:
            android.text.Layout$Alignment r0 = android.text.Layout.Alignment.ALIGN_CENTER
            return r0
        L74:
            android.text.Layout$Alignment r0 = android.text.Layout.Alignment.ALIGN_NORMAL
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.text.webvtt.WebvttCueParser.parseTextAlignment(java.lang.String):android.text.Layout$Alignment");
    }

    private static int findEndOfTag(String markup, int startPos) {
        int index = markup.indexOf(62, startPos);
        return index == -1 ? markup.length() : index + 1;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0042  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void applyEntity(java.lang.String r5, android.text.SpannableStringBuilder r6) {
        /*
            int r0 = r5.hashCode()
            r1 = 3309(0xced, float:4.637E-42)
            r2 = 3
            r3 = 2
            r4 = 1
            if (r0 == r1) goto L38
            r1 = 3464(0xd88, float:4.854E-42)
            if (r0 == r1) goto L2e
            r1 = 96708(0x179c4, float:1.35517E-40)
            if (r0 == r1) goto L24
            r1 = 3374865(0x337f11, float:4.729193E-39)
            if (r0 == r1) goto L1a
        L19:
            goto L42
        L1a:
            java.lang.String r0 = "nbsp"
            boolean r0 = r5.equals(r0)
            if (r0 == 0) goto L19
            r0 = 2
            goto L43
        L24:
            java.lang.String r0 = "amp"
            boolean r0 = r5.equals(r0)
            if (r0 == 0) goto L19
            r0 = 3
            goto L43
        L2e:
            java.lang.String r0 = "lt"
            boolean r0 = r5.equals(r0)
            if (r0 == 0) goto L19
            r0 = 0
            goto L43
        L38:
            java.lang.String r0 = "gt"
            boolean r0 = r5.equals(r0)
            if (r0 == 0) goto L19
            r0 = 1
            goto L43
        L42:
            r0 = -1
        L43:
            if (r0 == 0) goto L79
            if (r0 == r4) goto L73
            if (r0 == r3) goto L6d
            if (r0 == r2) goto L67
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "ignoring unsupported entity: '&"
            r0.append(r1)
            r0.append(r5)
            java.lang.String r1 = ";'"
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            java.lang.String r1 = "WebvttCueParser"
            com.google.android.exoplayer2.util.Log.w(r1, r0)
            goto L7f
        L67:
            r0 = 38
            r6.append(r0)
            goto L7f
        L6d:
            r0 = 32
            r6.append(r0)
            goto L7f
        L73:
            r0 = 62
            r6.append(r0)
            goto L7f
        L79:
            r0 = 60
            r6.append(r0)
        L7f:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.text.webvtt.WebvttCueParser.applyEntity(java.lang.String, android.text.SpannableStringBuilder):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x0060  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static boolean isSupportedTag(java.lang.String r8) {
        /*
            int r0 = r8.hashCode()
            r1 = 98
            r2 = 0
            r3 = 5
            r4 = 4
            r5 = 3
            r6 = 2
            r7 = 1
            if (r0 == r1) goto L56
            r1 = 99
            if (r0 == r1) goto L4c
            r1 = 105(0x69, float:1.47E-43)
            if (r0 == r1) goto L42
            r1 = 3314158(0x3291ee, float:4.644125E-39)
            if (r0 == r1) goto L38
            r1 = 117(0x75, float:1.64E-43)
            if (r0 == r1) goto L2e
            r1 = 118(0x76, float:1.65E-43)
            if (r0 == r1) goto L24
        L23:
            goto L60
        L24:
            java.lang.String r0 = "v"
            boolean r0 = r8.equals(r0)
            if (r0 == 0) goto L23
            r0 = 5
            goto L61
        L2e:
            java.lang.String r0 = "u"
            boolean r0 = r8.equals(r0)
            if (r0 == 0) goto L23
            r0 = 4
            goto L61
        L38:
            java.lang.String r0 = "lang"
            boolean r0 = r8.equals(r0)
            if (r0 == 0) goto L23
            r0 = 3
            goto L61
        L42:
            java.lang.String r0 = "i"
            boolean r0 = r8.equals(r0)
            if (r0 == 0) goto L23
            r0 = 2
            goto L61
        L4c:
            java.lang.String r0 = "c"
            boolean r0 = r8.equals(r0)
            if (r0 == 0) goto L23
            r0 = 1
            goto L61
        L56:
            java.lang.String r0 = "b"
            boolean r0 = r8.equals(r0)
            if (r0 == 0) goto L23
            r0 = 0
            goto L61
        L60:
            r0 = -1
        L61:
            if (r0 == 0) goto L6e
            if (r0 == r7) goto L6e
            if (r0 == r6) goto L6e
            if (r0 == r5) goto L6e
            if (r0 == r4) goto L6e
            if (r0 == r3) goto L6e
            return r2
        L6e:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.text.webvtt.WebvttCueParser.isSupportedTag(java.lang.String):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x0070  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void applySpansForTag(java.lang.String r7, com.google.android.exoplayer2.text.webvtt.WebvttCueParser.StartTag r8, android.text.SpannableStringBuilder r9, java.util.List<com.google.android.exoplayer2.text.webvtt.WebvttCssStyle> r10, java.util.List<com.google.android.exoplayer2.text.webvtt.WebvttCueParser.StyleMatch> r11) {
        /*
            int r0 = r8.position
            int r1 = r9.length()
            java.lang.String r2 = r8.name
            int r3 = r2.hashCode()
            r4 = 2
            r5 = 1
            if (r3 == 0) goto L66
            r6 = 105(0x69, float:1.47E-43)
            if (r3 == r6) goto L5c
            r6 = 3314158(0x3291ee, float:4.644125E-39)
            if (r3 == r6) goto L52
            r6 = 98
            if (r3 == r6) goto L48
            r6 = 99
            if (r3 == r6) goto L3e
            r6 = 117(0x75, float:1.64E-43)
            if (r3 == r6) goto L34
            r6 = 118(0x76, float:1.65E-43)
            if (r3 == r6) goto L2a
        L29:
            goto L70
        L2a:
            java.lang.String r3 = "v"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L29
            r2 = 5
            goto L71
        L34:
            java.lang.String r3 = "u"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L29
            r2 = 2
            goto L71
        L3e:
            java.lang.String r3 = "c"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L29
            r2 = 3
            goto L71
        L48:
            java.lang.String r3 = "b"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L29
            r2 = 0
            goto L71
        L52:
            java.lang.String r3 = "lang"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L29
            r2 = 4
            goto L71
        L5c:
            java.lang.String r3 = "i"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L29
            r2 = 1
            goto L71
        L66:
            java.lang.String r3 = ""
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L29
            r2 = 6
            goto L71
        L70:
            r2 = -1
        L71:
            r3 = 33
            switch(r2) {
                case 0: goto L8a;
                case 1: goto L81;
                case 2: goto L78;
                case 3: goto L77;
                case 4: goto L77;
                case 5: goto L77;
                case 6: goto L77;
                default: goto L76;
            }
        L76:
            return
        L77:
            goto L93
        L78:
            android.text.style.UnderlineSpan r2 = new android.text.style.UnderlineSpan
            r2.<init>()
            r9.setSpan(r2, r0, r1, r3)
            goto L93
        L81:
            android.text.style.StyleSpan r2 = new android.text.style.StyleSpan
            r2.<init>(r4)
            r9.setSpan(r2, r0, r1, r3)
            goto L93
        L8a:
            android.text.style.StyleSpan r2 = new android.text.style.StyleSpan
            r2.<init>(r5)
            r9.setSpan(r2, r0, r1, r3)
        L93:
            r11.clear()
            getApplicableStyles(r10, r7, r8, r11)
            int r2 = r11.size()
            r3 = 0
        L9e:
            if (r3 >= r2) goto Lae
            java.lang.Object r4 = r11.get(r3)
            com.google.android.exoplayer2.text.webvtt.WebvttCueParser$StyleMatch r4 = (com.google.android.exoplayer2.text.webvtt.WebvttCueParser.StyleMatch) r4
            com.google.android.exoplayer2.text.webvtt.WebvttCssStyle r4 = r4.style
            applyStyleToText(r9, r4, r0, r1)
            int r3 = r3 + 1
            goto L9e
        Lae:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.text.webvtt.WebvttCueParser.applySpansForTag(java.lang.String, com.google.android.exoplayer2.text.webvtt.WebvttCueParser$StartTag, android.text.SpannableStringBuilder, java.util.List, java.util.List):void");
    }

    private static void applyStyleToText(SpannableStringBuilder spannedText, WebvttCssStyle style, int start, int end) {
        if (style == null) {
            return;
        }
        if (style.getStyle() != -1) {
            spannedText.setSpan(new StyleSpan(style.getStyle()), start, end, 33);
        }
        if (style.isLinethrough()) {
            spannedText.setSpan(new StrikethroughSpan(), start, end, 33);
        }
        if (style.isUnderline()) {
            spannedText.setSpan(new UnderlineSpan(), start, end, 33);
        }
        if (style.hasFontColor()) {
            spannedText.setSpan(new ForegroundColorSpan(style.getFontColor()), start, end, 33);
        }
        if (style.hasBackgroundColor()) {
            spannedText.setSpan(new BackgroundColorSpan(style.getBackgroundColor()), start, end, 33);
        }
        if (style.getFontFamily() != null) {
            spannedText.setSpan(new TypefaceSpan(style.getFontFamily()), start, end, 33);
        }
        if (style.getTextAlign() != null) {
            spannedText.setSpan(new AlignmentSpan.Standard(style.getTextAlign()), start, end, 33);
        }
        int fontSizeUnit = style.getFontSizeUnit();
        if (fontSizeUnit == 1) {
            spannedText.setSpan(new AbsoluteSizeSpan((int) style.getFontSize(), true), start, end, 33);
        } else if (fontSizeUnit == 2) {
            spannedText.setSpan(new RelativeSizeSpan(style.getFontSize()), start, end, 33);
        } else if (fontSizeUnit == 3) {
            spannedText.setSpan(new RelativeSizeSpan(style.getFontSize() / 100.0f), start, end, 33);
        }
    }

    private static String getTagName(String tagExpression) {
        String tagExpression2 = tagExpression.trim();
        if (tagExpression2.isEmpty()) {
            return null;
        }
        return Util.splitAtFirst(tagExpression2, "[ \\.]")[0];
    }

    private static void getApplicableStyles(List<WebvttCssStyle> declaredStyles, String id, StartTag tag, List<StyleMatch> output) {
        int styleCount = declaredStyles.size();
        for (int i = 0; i < styleCount; i++) {
            WebvttCssStyle style = declaredStyles.get(i);
            int score = style.getSpecificityScore(id, tag.name, tag.classes, tag.voice);
            if (score > 0) {
                output.add(new StyleMatch(score, style));
            }
        }
        Collections.sort(output);
    }

    private static final class StyleMatch implements Comparable<StyleMatch> {
        public final int score;
        public final WebvttCssStyle style;

        public StyleMatch(int score, WebvttCssStyle style) {
            this.score = score;
            this.style = style;
        }

        @Override // java.lang.Comparable
        public int compareTo(StyleMatch another) {
            return this.score - another.score;
        }
    }

    private static final class StartTag {
        private static final String[] NO_CLASSES = new String[0];
        public final String[] classes;
        public final String name;
        public final int position;
        public final String voice;

        private StartTag(String name, int position, String voice, String[] classes) {
            this.position = position;
            this.name = name;
            this.voice = voice;
            this.classes = classes;
        }

        public static StartTag buildStartTag(String fullTagExpression, int position) {
            String voice;
            String[] classes;
            String fullTagExpression2 = fullTagExpression.trim();
            if (fullTagExpression2.isEmpty()) {
                return null;
            }
            int voiceStartIndex = fullTagExpression2.indexOf(" ");
            if (voiceStartIndex == -1) {
                voice = "";
            } else {
                String voice2 = fullTagExpression2.substring(voiceStartIndex);
                voice = voice2.trim();
                fullTagExpression2 = fullTagExpression2.substring(0, voiceStartIndex);
            }
            String[] nameAndClasses = Util.split(fullTagExpression2, "\\.");
            String name = nameAndClasses[0];
            if (nameAndClasses.length > 1) {
                classes = (String[]) Arrays.copyOfRange(nameAndClasses, 1, nameAndClasses.length);
            } else {
                classes = NO_CLASSES;
            }
            return new StartTag(name, position, voice, classes);
        }

        public static StartTag buildWholeCueVirtualTag() {
            return new StartTag("", 0, "", new String[0]);
        }
    }
}
