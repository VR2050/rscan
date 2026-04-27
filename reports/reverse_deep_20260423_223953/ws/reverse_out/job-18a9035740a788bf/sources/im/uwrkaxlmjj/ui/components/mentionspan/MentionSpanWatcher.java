package im.uwrkaxlmjj.ui.components.mentionspan;

import android.text.Selection;
import android.text.Spannable;
import android.text.style.ForegroundColorSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.watcher.SpanWatcherAdapter;

/* JADX INFO: loaded from: classes5.dex */
public class MentionSpanWatcher extends SpanWatcherAdapter {
    private int selectStart = 0;
    private int selectEnd = 0;

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.watcher.SpanWatcherAdapter, android.text.SpanWatcher
    public void onSpanChanged(Spannable text, Object what, int ostart, int oend, int nstart, int nend) {
        ForegroundColorSpan span;
        ForegroundColorSpan span2;
        if (what == Selection.SELECTION_END && this.selectEnd != nstart) {
            this.selectEnd = nstart;
            ForegroundColorSpan[] spans = (ForegroundColorSpan[]) text.getSpans(nstart, nend, ForegroundColorSpan.class);
            if (spans != null && spans.length > 0 && (span2 = spans[0]) != null) {
                int spanStart = text.getSpanStart(span2);
                int spanEnd = text.getSpanEnd(span2);
                int index = Math.abs(this.selectEnd - spanEnd) > Math.abs(this.selectEnd - spanStart) ? spanStart : spanEnd;
                Selection.setSelection(text, Selection.getSelectionStart(text), index);
            }
        }
        if (what == Selection.SELECTION_START && this.selectStart != nstart) {
            this.selectStart = nstart;
            ForegroundColorSpan[] spans2 = (ForegroundColorSpan[]) text.getSpans(nstart, nend, ForegroundColorSpan.class);
            if (spans2 != null && spans2.length > 0 && (span = spans2[0]) != null) {
                int spanStart2 = text.getSpanStart(span);
                int spanEnd2 = text.getSpanEnd(span);
                int index2 = Math.abs(this.selectStart - spanEnd2) > Math.abs(this.selectStart - spanStart2) ? spanStart2 : spanEnd2;
                Selection.setSelection(text, index2, Selection.getSelectionEnd(text));
            }
        }
    }
}
