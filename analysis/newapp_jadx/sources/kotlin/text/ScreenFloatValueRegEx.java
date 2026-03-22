package kotlin.text;

import kotlin.Metadata;
import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5310d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\bÂ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u0010\u0010\u0003\u001a\u00020\u00048\u0006X\u0087\u0004¢\u0006\u0002\n\u0000¨\u0006\u0005"}, m5311d2 = {"Lkotlin/text/ScreenFloatValueRegEx;", "", "()V", "value", "Lkotlin/text/Regex;", "kotlin-stdlib"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public final class ScreenFloatValueRegEx {

    @NotNull
    public static final ScreenFloatValueRegEx INSTANCE = new ScreenFloatValueRegEx();

    @JvmField
    @NotNull
    public static final Regex value;

    static {
        StringBuilder sb = new StringBuilder();
        sb.append('(');
        sb.append("(\\p{Digit}+)");
        sb.append("(\\.)?(");
        sb.append("(\\p{Digit}+)");
        sb.append("?)(");
        C1499a.m608b0(sb, "[eE][+-]?(\\p{Digit}+)", ")?)|(\\.(", "(\\p{Digit}+)", ")(");
        C1499a.m608b0(sb, "[eE][+-]?(\\p{Digit}+)", ")?)|((", "(0[xX](\\p{XDigit}+)(\\.)?)|(0[xX](\\p{XDigit}+)?(\\.)(\\p{XDigit}+))", ")[pP][+-]?");
        value = new Regex(C1499a.m639y("[\\x00-\\x20]*[+-]?(NaN|Infinity|((", C1499a.m581C(sb, "(\\p{Digit}+)", ')'), ")[fFdD]?))[\\x00-\\x20]*"));
    }

    private ScreenFloatValueRegEx() {
    }
}
