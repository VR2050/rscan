package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method;

import android.text.Editable;
import android.text.Spannable;
import android.view.KeyEvent;
import android.view.View;
import android.widget.EditText;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.KeyCodeDeleteHelper;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.NoCopySpanEditableFactory;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.SpanFactory;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.DataBindingSpan;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.User;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.watcher.SelectionSpanWatcher;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.webrtc.mozi.CodecMonitorHelper;

/* JADX INFO: compiled from: AtUserMethod.kt */
/* JADX INFO: loaded from: classes5.dex */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\bÆ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u0010\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0006H\u0016J\u0010\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nH\u0016¨\u0006\u000b"}, d2 = {"Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/method/AtUserMethod;", "Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/method/Method;", "()V", CodecMonitorHelper.EVENT_INIT, "", "editText", "Landroid/widget/EditText;", "newSpannable", "Landroid/text/Spannable;", "atUserSpan", "Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/span/AtUserSpan;", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
public final class AtUserMethod implements Method {
    public static final AtUserMethod INSTANCE = new AtUserMethod();

    private AtUserMethod() {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method.Method
    public void init(EditText editText) {
        Intrinsics.checkParameterIsNotNull(editText, "editText");
        editText.setText((CharSequence) null);
        editText.setEditableFactory(new NoCopySpanEditableFactory(new SelectionSpanWatcher(Reflection.getOrCreateKotlinClass(DataBindingSpan.class))));
        editText.setOnKeyListener(new View.OnKeyListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method.AtUserMethod.init.1
            @Override // android.view.View.OnKeyListener
            public final boolean onKey(View v, int keyCode, KeyEvent event) {
                if (keyCode != 67) {
                    return false;
                }
                Intrinsics.checkExpressionValueIsNotNull(event, "event");
                if (event.getAction() == 0) {
                    KeyCodeDeleteHelper keyCodeDeleteHelper = KeyCodeDeleteHelper.INSTANCE;
                    if (v != null) {
                        Editable text = ((EditText) v).getText();
                        Intrinsics.checkExpressionValueIsNotNull(text, "(v as EditText).text");
                        return keyCodeDeleteHelper.onDelDown(text);
                    }
                    throw new TypeCastException("null cannot be cast to non-null type android.widget.EditText");
                }
                return false;
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method.Method
    public Spannable newSpannable(User atUserSpan) {
        Intrinsics.checkParameterIsNotNull(atUserSpan, "atUserSpan");
        return SpanFactory.INSTANCE.newSpannable(atUserSpan.getSpannedName(), atUserSpan);
    }
}
