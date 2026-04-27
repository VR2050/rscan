package im.uwrkaxlmjj.ui.hui.adapter;

import android.text.InputFilter;
import android.text.Spanned;
import android.text.TextUtils;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes5.dex */
public class InputNumberFilter implements InputFilter {
    private int max;
    Pattern p = Pattern.compile("([0-9])*");

    public InputNumberFilter(int max) {
        this.max = SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION;
        this.max = max;
    }

    @Override // android.text.InputFilter
    public CharSequence filter(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) {
        String sourceText = source.toString();
        String destText = dest.toString();
        if (TextUtils.isEmpty(sourceText)) {
            return "";
        }
        Matcher matcher = this.p.matcher(source);
        if (!matcher.matches()) {
            return "";
        }
        if ("0".equals(source.toString()) && dstart == 0) {
            return "";
        }
        String first = destText.substring(0, dstart);
        String second = destText.substring(dstart);
        String sum = first + sourceText + second;
        double sumText = Double.parseDouble(sum);
        int i = this.max;
        if (i > -1 && sumText > i) {
            return dest.subSequence(dstart, dend);
        }
        return ((Object) dest.subSequence(dstart, dend)) + sourceText;
    }
}
