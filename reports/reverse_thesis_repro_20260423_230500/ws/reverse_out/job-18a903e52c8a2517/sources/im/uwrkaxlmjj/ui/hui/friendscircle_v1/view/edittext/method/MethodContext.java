package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method;

import android.text.Spannable;
import android.widget.EditText;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.User;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.webrtc.mozi.CodecMonitorHelper;

/* JADX INFO: compiled from: MethodContext.kt */
/* JADX INFO: loaded from: classes5.dex */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0010\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000bH\u0016J\u0010\u0010\f\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\u000fH\u0016R\u001c\u0010\u0003\u001a\u0004\u0018\u00010\u0001X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0004\u0010\u0005\"\u0004\b\u0006\u0010\u0007¨\u0006\u0010"}, d2 = {"Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/method/MethodContext;", "Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/method/Method;", "()V", "method", "getMethod", "()Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/method/Method;", "setMethod", "(Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/method/Method;)V", CodecMonitorHelper.EVENT_INIT, "", "editText", "Landroid/widget/EditText;", "newSpannable", "Landroid/text/Spannable;", "atUserSpan", "Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/span/AtUserSpan;", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
public final class MethodContext implements Method {
    private Method method;

    public final Method getMethod() {
        return this.method;
    }

    public final void setMethod(Method method) {
        this.method = method;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method.Method
    public void init(EditText editText) {
        Intrinsics.checkParameterIsNotNull(editText, "editText");
        Method method = this.method;
        if (method != null) {
            method.init(editText);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method.Method
    public Spannable newSpannable(User atUserSpan) {
        Spannable spannableNewSpannable;
        Intrinsics.checkParameterIsNotNull(atUserSpan, "atUserSpan");
        Method method = this.method;
        if (method == null || (spannableNewSpannable = method.newSpannable(atUserSpan)) == null) {
            throw new NullPointerException("method: null");
        }
        return spannableNewSpannable;
    }
}
