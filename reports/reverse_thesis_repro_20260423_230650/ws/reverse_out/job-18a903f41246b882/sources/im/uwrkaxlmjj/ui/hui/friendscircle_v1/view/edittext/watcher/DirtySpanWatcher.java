package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.watcher;

import android.text.Spannable;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.DirtySpan;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* JADX INFO: compiled from: DirtySpanWatcher.kt */
/* JADX INFO: loaded from: classes5.dex */
@Metadata(bv = {1, 0, 3}, d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u0019\u0012\u0012\u0010\u0002\u001a\u000e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u00050\u0003¢\u0006\u0002\u0010\u0006J8\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\u00042\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\r2\u0006\u0010\u000f\u001a\u00020\r2\u0006\u0010\u0010\u001a\u00020\rH\u0016R\u001a\u0010\u0002\u001a\u000e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u00050\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0011"}, d2 = {"Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/watcher/DirtySpanWatcher;", "Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/watcher/SpanWatcherAdapter;", "removePredicate", "Lkotlin/Function1;", "", "", "(Lkotlin/jvm/functions/Function1;)V", "onSpanChanged", "", "text", "Landroid/text/Spannable;", "what", "ostart", "", "oend", "nstart", "nend", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
public final class DirtySpanWatcher extends SpanWatcherAdapter {
    private final Function1<Object, Boolean> removePredicate;

    public DirtySpanWatcher(Function1<Object, Boolean> removePredicate) {
        Intrinsics.checkParameterIsNotNull(removePredicate, "removePredicate");
        this.removePredicate = removePredicate;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.watcher.SpanWatcherAdapter, android.text.SpanWatcher
    public void onSpanChanged(Spannable text, Object what, int ostart, int oend, int nstart, int nend) {
        Intrinsics.checkParameterIsNotNull(text, "text");
        Intrinsics.checkParameterIsNotNull(what, "what");
        if ((what instanceof DirtySpan) && ((DirtySpan) what).isDirty(text)) {
            int spanStart = text.getSpanStart(what);
            int spanEnd = text.getSpanEnd(what);
            Object[] $this$filter$iv = text.getSpans(spanStart, spanEnd, Object.class);
            Intrinsics.checkExpressionValueIsNotNull($this$filter$iv, "text.getSpans(spanStart, spanEnd, Any::class.java)");
            Collection destination$iv$iv = new ArrayList();
            for (Object it : $this$filter$iv) {
                Function1<Object, Boolean> function1 = this.removePredicate;
                Intrinsics.checkExpressionValueIsNotNull(it, "it");
                if (function1.invoke(it).booleanValue()) {
                    destination$iv$iv.add(it);
                }
            }
            Iterable $this$forEach$iv = (List) destination$iv$iv;
            for (Object element$iv : $this$forEach$iv) {
                text.removeSpan(element$iv);
            }
        }
    }
}
