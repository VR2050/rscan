package im.uwrkaxlmjj.ui.hui.adapter;

import android.text.InputFilter;
import android.text.Spanned;
import android.text.TextUtils;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes5.dex */
public class EditInputFilter implements InputFilter {
    public static final int MAX_VALUE = 1000000;
    private static final String POINTER = ".";
    public static final int POINTER_LENGTH = 2;
    Pattern p;

    public EditInputFilter() {
        this.p = Pattern.compile("([0-9]|\\.)*");
    }

    public EditInputFilter(boolean posInteger) {
        if (posInteger) {
            this.p = Pattern.compile("([0-9])*");
        }
    }

    @Override // android.text.InputFilter
    public CharSequence filter(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) {
        String sourceText = source.toString();
        String destText = dest.toString();
        if (TextUtils.isEmpty(sourceText)) {
            return (dstart == 0 && destText.indexOf(POINTER) == 1) ? "0" : "";
        }
        Matcher matcher = this.p.matcher(source);
        if (destText.contains(POINTER)) {
            if (!matcher.matches() || POINTER.equals(source)) {
                return "";
            }
            int index = destText.indexOf(POINTER);
            int length = destText.trim().length() - index;
            if (length > 2 && dstart > index) {
                return "";
            }
        } else {
            if (!matcher.matches()) {
                return "";
            }
            if (POINTER.equals(source) && dstart == 0) {
                return "0.";
            }
            if ("0".equals(source) && dstart == 0) {
                return "0";
            }
        }
        String first = destText.substring(0, dstart);
        String second = destText.substring(dstart, destText.length());
        String sum = first + sourceText + second;
        double sumText = Double.parseDouble(sum);
        if (sumText > 1000000.0d) {
            return dest.subSequence(dstart, dend);
        }
        return ((Object) dest.subSequence(dstart, dend)) + sourceText;
    }
}
