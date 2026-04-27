package im.uwrkaxlmjj.ui.components;

import android.os.Build;
import android.text.Layout;
import android.text.SpannableStringBuilder;
import android.text.StaticLayout;
import android.text.TextDirectionHeuristic;
import android.text.TextDirectionHeuristics;
import android.text.TextPaint;
import android.text.TextUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import java.lang.reflect.Constructor;

/* JADX INFO: loaded from: classes5.dex */
public class StaticLayoutEx {
    private static final String TEXT_DIRS_CLASS = "android.text.TextDirectionHeuristics";
    private static final String TEXT_DIR_CLASS = "android.text.TextDirectionHeuristic";
    private static final String TEXT_DIR_FIRSTSTRONG_LTR = "FIRSTSTRONG_LTR";
    public static Layout.Alignment[] alignments = Layout.Alignment.values();
    private static boolean initialized;
    private static Constructor<StaticLayout> sConstructor;
    private static Object[] sConstructorArgs;
    private static Object sTextDirection;

    public static Layout.Alignment ALIGN_RIGHT() {
        Layout.Alignment[] alignmentArr = alignments;
        return alignmentArr.length >= 5 ? alignmentArr[4] : Layout.Alignment.ALIGN_OPPOSITE;
    }

    public static Layout.Alignment ALIGN_LEFT() {
        Layout.Alignment[] alignmentArr = alignments;
        return alignmentArr.length >= 5 ? alignmentArr[3] : Layout.Alignment.ALIGN_NORMAL;
    }

    public static void init() {
        Class<?> textDirClass;
        if (initialized) {
            return;
        }
        try {
            if (Build.VERSION.SDK_INT >= 18) {
                textDirClass = TextDirectionHeuristic.class;
                sTextDirection = TextDirectionHeuristics.FIRSTSTRONG_LTR;
            } else {
                ClassLoader loader = StaticLayoutEx.class.getClassLoader();
                Class<?> textDirClass2 = loader.loadClass(TEXT_DIR_CLASS);
                Class<?> textDirsClass = loader.loadClass(TEXT_DIRS_CLASS);
                sTextDirection = textDirsClass.getField(TEXT_DIR_FIRSTSTRONG_LTR).get(textDirsClass);
                textDirClass = textDirClass2;
            }
            Class<?>[] signature = {CharSequence.class, Integer.TYPE, Integer.TYPE, TextPaint.class, Integer.TYPE, Layout.Alignment.class, textDirClass, Float.TYPE, Float.TYPE, Boolean.TYPE, TextUtils.TruncateAt.class, Integer.TYPE, Integer.TYPE};
            Constructor<StaticLayout> declaredConstructor = StaticLayout.class.getDeclaredConstructor(signature);
            sConstructor = declaredConstructor;
            declaredConstructor.setAccessible(true);
            sConstructorArgs = new Object[signature.length];
            initialized = true;
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    public static StaticLayout createStaticLayout2(CharSequence source, TextPaint paint, int width, Layout.Alignment align, float spacingmult, float spacingadd, boolean includepad, TextUtils.TruncateAt ellipsize, int ellipsisWidth, int maxLines) {
        if (Build.VERSION.SDK_INT < 23) {
            return createStaticLayout(source, 0, source.length(), paint, width, align, spacingmult, spacingadd, includepad, ellipsize, ellipsisWidth, maxLines, true);
        }
        StaticLayout.Builder builder = StaticLayout.Builder.obtain(source, 0, source.length(), paint, ellipsisWidth).setAlignment(align).setLineSpacing(spacingadd, spacingmult).setIncludePad(includepad).setEllipsize(TextUtils.TruncateAt.END).setEllipsizedWidth(ellipsisWidth).setMaxLines(maxLines).setBreakStrategy(1).setHyphenationFrequency(0);
        return builder.build();
    }

    public static StaticLayout createStaticLayout(CharSequence source, TextPaint paint, int width, Layout.Alignment align, float spacingmult, float spacingadd, boolean includepad, TextUtils.TruncateAt ellipsize, int ellipsisWidth, int maxLines) {
        return createStaticLayout(source, 0, source.length(), paint, width, align, spacingmult, spacingadd, includepad, ellipsize, ellipsisWidth, maxLines, true);
    }

    public static StaticLayout createStaticLayout(CharSequence source, TextPaint paint, int width, Layout.Alignment align, float spacingmult, float spacingadd, boolean includepad, TextUtils.TruncateAt ellipsize, int ellipsisWidth, int maxLines, boolean canContainUrl) {
        return createStaticLayout(source, 0, source.length(), paint, width, align, spacingmult, spacingadd, includepad, ellipsize, ellipsisWidth, maxLines, canContainUrl);
    }

    public static StaticLayout createStaticLayoutMiddle(CharSequence source, TextPaint paint, int width, Layout.Alignment align, float spacingmult, float spacingadd, boolean includepad, TextUtils.TruncateAt ellipsize, int ellipsisWidth, int maxLines, boolean canContainUrl) {
        return createStaticLayoutMiddle(source, 0, source.length(), paint, width, align, spacingmult, spacingadd, includepad, ellipsize, ellipsisWidth, maxLines, canContainUrl);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v7, types: [android.text.StaticLayout$Builder] */
    /* JADX WARN: Type inference failed for: r10v8, types: [android.text.StaticLayout$Builder] */
    /* JADX WARN: Type inference failed for: r11v0 */
    /* JADX WARN: Type inference failed for: r12v0 */
    /* JADX WARN: Type inference failed for: r15v1 */
    /* JADX WARN: Type inference failed for: r15v2 */
    /* JADX WARN: Type inference failed for: r15v3, types: [android.text.TextUtils$TruncateAt] */
    /* JADX WARN: Type inference failed for: r15v4 */
    /* JADX WARN: Type inference failed for: r1v22, types: [android.text.StaticLayout$Builder] */
    /* JADX WARN: Type inference failed for: r2v0, types: [android.text.TextUtils$TruncateAt] */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v13 */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r3v0, types: [boolean] */
    /* JADX WARN: Type inference failed for: r3v1 */
    /* JADX WARN: Type inference failed for: r3v2 */
    /* JADX WARN: Type inference failed for: r3v4 */
    /* JADX WARN: Type inference failed for: r3v5 */
    /* JADX WARN: Type inference failed for: r3v6 */
    /* JADX WARN: Type inference failed for: r8v0, types: [android.text.TextPaint] */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v2 */
    /* JADX WARN: Type inference failed for: r8v4 */
    /* JADX WARN: Type inference failed for: r8v5 */
    /* JADX WARN: Type inference failed for: r8v6 */
    public static StaticLayout createStaticLayoutMiddle(CharSequence charSequence, int i, int i2, TextPaint textPaint, int i3, Layout.Alignment alignment, float f, float f2, boolean z, TextUtils.TruncateAt truncateAt, int i4, int i5, boolean z2) {
        int i6;
        int i7;
        ?? r15;
        StaticLayout staticLayout;
        int offsetForHorizontal;
        int i8;
        ?? r8 = textPaint;
        ?? r3 = z;
        ?? r2 = truncateAt;
        int lineCount = i4;
        int i9 = 1;
        try {
            if (i5 == 1) {
                CharSequence charSequenceEllipsize = TextUtils.ellipsize(charSequence, r8, lineCount, r2);
                return new StaticLayout(charSequenceEllipsize, 0, charSequenceEllipsize.length(), textPaint, i3, alignment, f, f2, z);
            }
            try {
                if (Build.VERSION.SDK_INT >= 23) {
                    i6 = i5;
                    staticLayout = StaticLayout.Builder.obtain(charSequence, 0, charSequence.length(), r8, i3).setAlignment(alignment).setLineSpacing(f2, f).setIncludePad(r3).setEllipsize(r2).setEllipsizedWidth(lineCount).setMaxLines(i6).setBreakStrategy(1).setHyphenationFrequency(0).build();
                    i7 = lineCount;
                    r15 = r2;
                    r2 = r2;
                    r3 = r3;
                    r8 = r8;
                } else {
                    i6 = i5;
                    i7 = lineCount;
                    r15 = r2;
                    CharSequence charSequence2 = charSequence;
                    TextPaint textPaint2 = textPaint;
                    boolean z3 = z;
                    try {
                        staticLayout = new StaticLayout(charSequence2, textPaint2, i3, alignment, f, f2, z3);
                        r2 = charSequence2;
                        r3 = textPaint2;
                        r8 = z3;
                    } catch (Exception e) {
                        e = e;
                        FileLog.e(e);
                        return null;
                    }
                }
                lineCount = staticLayout.getLineCount();
                if (lineCount <= i6) {
                    return staticLayout;
                }
                float lineLeft = staticLayout.getLineLeft(i6 - 1);
                float lineWidth = staticLayout.getLineWidth(i6 - 1);
                if (lineLeft != 0.0f) {
                    offsetForHorizontal = staticLayout.getOffsetForHorizontal(i6 - 1, lineLeft);
                } else {
                    offsetForHorizontal = staticLayout.getOffsetForHorizontal(i6 - 1, lineWidth);
                }
                if (lineWidth >= i7 - AndroidUtilities.dp(10.0f)) {
                    i8 = offsetForHorizontal;
                } else {
                    i8 = offsetForHorizontal + 3;
                }
                SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(charSequence.subSequence(0, Math.max(0, i8 - 3)));
                spannableStringBuilder.append((CharSequence) "…");
                try {
                    if (Build.VERSION.SDK_INT < 23) {
                        return new StaticLayout(spannableStringBuilder, textPaint, i3, alignment, f, f2, z);
                    }
                    try {
                    } catch (Exception e2) {
                        e = e2;
                    }
                    try {
                    } catch (Exception e3) {
                        e = e3;
                        FileLog.e(e);
                        return null;
                    }
                    try {
                    } catch (Exception e4) {
                        e = e4;
                        FileLog.e(e);
                        return null;
                    }
                    try {
                        StaticLayout.Builder maxLines = StaticLayout.Builder.obtain(spannableStringBuilder, 0, spannableStringBuilder.length(), textPaint, i3).setAlignment(alignment).setLineSpacing(f2, f).setIncludePad(z).setEllipsize(r15).setEllipsizedWidth(i7).setMaxLines(i6);
                        if (!z2) {
                            i9 = 0;
                        }
                        return maxLines.setBreakStrategy(i9).setHyphenationFrequency(0).build();
                    } catch (Exception e5) {
                        e = e5;
                        FileLog.e(e);
                        return null;
                    }
                } catch (Exception e6) {
                    e = e6;
                    FileLog.e(e);
                    return null;
                }
            } catch (Exception e7) {
                e = e7;
                FileLog.e(e);
                return null;
            }
        } catch (Exception e8) {
            e = e8;
        }
    }

    public static StaticLayout createStaticLayout(CharSequence source, int bufstart, int bufend, TextPaint paint, int outerWidth, Layout.Alignment align, float spacingMult, float spacingAdd, boolean includePad, TextUtils.TruncateAt ellipsize, int ellipsisWidth, int maxLines, boolean canContainUrl) {
        int i;
        int i2;
        boolean z;
        StaticLayout layout;
        int off;
        int off2;
        try {
            if (maxLines == 1) {
                CharSequence text = TextUtils.ellipsize(source, paint, ellipsisWidth, TextUtils.TruncateAt.END);
                return new StaticLayout(text, 0, text.length(), paint, outerWidth, align, spacingMult, spacingAdd, includePad);
            }
            if (Build.VERSION.SDK_INT >= 23) {
                StaticLayout.Builder builder = StaticLayout.Builder.obtain(source, 0, source.length(), paint, outerWidth).setAlignment(align).setLineSpacing(spacingAdd, spacingMult).setIncludePad(includePad).setEllipsize(null).setEllipsizedWidth(ellipsisWidth).setMaxLines(maxLines).setBreakStrategy(1).setHyphenationFrequency(0);
                layout = builder.build();
                i = maxLines;
                i2 = ellipsisWidth;
                z = includePad;
            } else {
                i = maxLines;
                i2 = ellipsisWidth;
                z = includePad;
                try {
                    layout = new StaticLayout(source, paint, outerWidth, align, spacingMult, spacingAdd, includePad);
                } catch (Exception e) {
                    e = e;
                    FileLog.e(e);
                    return null;
                }
            }
            if (layout.getLineCount() <= i) {
                return layout;
            }
            float left = layout.getLineLeft(i - 1);
            float lineWidth = layout.getLineWidth(i - 1);
            if (left != 0.0f) {
                off = layout.getOffsetForHorizontal(i - 1, left);
            } else {
                int off3 = i - 1;
                off = layout.getOffsetForHorizontal(off3, lineWidth);
            }
            if (lineWidth >= i2 - AndroidUtilities.dp(10.0f)) {
                off2 = off;
            } else {
                off2 = off + 3;
            }
            SpannableStringBuilder stringBuilder = new SpannableStringBuilder(source.subSequence(0, Math.max(0, off2 - 3)));
            stringBuilder.append((CharSequence) "…");
            try {
                if (Build.VERSION.SDK_INT < 23) {
                    return new StaticLayout(stringBuilder, paint, outerWidth, align, spacingMult, spacingAdd, includePad);
                }
                try {
                } catch (Exception e2) {
                    e = e2;
                }
                try {
                } catch (Exception e3) {
                    e = e3;
                    FileLog.e(e);
                    return null;
                }
                try {
                    StaticLayout.Builder builder2 = StaticLayout.Builder.obtain(stringBuilder, 0, stringBuilder.length(), paint, outerWidth).setAlignment(align).setLineSpacing(spacingAdd, spacingMult).setIncludePad(z).setEllipsize(TextUtils.TruncateAt.END).setEllipsizedWidth(i2).setMaxLines(i).setBreakStrategy(canContainUrl ? 1 : 0).setHyphenationFrequency(0);
                    return builder2.build();
                } catch (Exception e4) {
                    e = e4;
                    FileLog.e(e);
                    return null;
                }
            } catch (Exception e5) {
                e = e5;
            }
        } catch (Exception e6) {
            e = e6;
        }
    }
}
