package im.uwrkaxlmjj.ui.components.filter;

import android.text.InputFilter;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import java.nio.charset.Charset;

/* JADX INFO: loaded from: classes5.dex */
public class MaxByteLengthFilter implements InputFilter {
    private boolean mAllowEmoji;
    private int mMaxAllowByteLength;

    public MaxByteLengthFilter() {
        this(48);
    }

    public MaxByteLengthFilter(int maxAllowByteLength) {
        this(maxAllowByteLength, true);
    }

    public MaxByteLengthFilter(int maxAllowByteLength, boolean allowEmoji) {
        this.mMaxAllowByteLength = maxAllowByteLength;
        this.mAllowEmoji = allowEmoji;
    }

    @Override // android.text.InputFilter
    public CharSequence filter(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) {
        boolean more = false;
        do {
            SpannableStringBuilder builder = new SpannableStringBuilder(dest).replace(dstart, dend, source.subSequence(start, end));
            if (AndroidUtilities.containsEmoji(source) && !this.mAllowEmoji) {
                source = "";
            } else {
                int len = builder.toString().getBytes(Charset.defaultCharset()).length;
                more = len > this.mMaxAllowByteLength;
                if (more) {
                    if (AndroidUtilities.containsEmoji(source) && this.mAllowEmoji) {
                        end = 0;
                        source = "";
                    } else {
                        end--;
                        source = source.subSequence(start, end);
                    }
                }
            }
        } while (more);
        return source;
    }
}
