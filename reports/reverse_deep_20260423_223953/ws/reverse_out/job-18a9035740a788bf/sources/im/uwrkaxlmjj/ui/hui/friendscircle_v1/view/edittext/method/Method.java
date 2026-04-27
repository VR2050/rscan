package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method;

import android.text.Spannable;
import android.widget.EditText;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.User;
import kotlin.Metadata;
import org.webrtc.mozi.CodecMonitorHelper;

/* JADX INFO: compiled from: Method.kt */
/* JADX INFO: loaded from: classes5.dex */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\bf\u0018\u00002\u00020\u0001J\u0010\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H&J\u0010\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\tH&¨\u0006\n"}, d2 = {"Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/method/Method;", "", CodecMonitorHelper.EVENT_INIT, "", "editText", "Landroid/widget/EditText;", "newSpannable", "Landroid/text/Spannable;", "atUserSpan", "Lim/uwrkaxlmjj/ui/hui/friendscircle_v1/view/edittext/span/AtUserSpan;", "HMessagesPrj_prodRelease"}, k = 1, mv = {1, 1, 16})
public interface Method {
    void init(EditText editText);

    Spannable newSpannable(User atUserSpan);
}
