package im.uwrkaxlmjj.tel;

import android.content.Context;
import android.database.ContentObserver;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Handler;
import android.os.Parcelable;
import android.telecom.Call;
import androidx.core.app.ActivityCompat;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;

/* JADX INFO: compiled from: CallInterceptor.kt */
/* JADX INFO: loaded from: classes2.dex */
@Metadata(bv = {1, 0, 3}, d1 = {"\u0000\u001e\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a\u0018\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H\u0002\u001a\u0012\u0010\u0006\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u0007\u001a\u00020\bH\u0003\u001a\u0010\u0010\t\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0003¨\u0006\n"}, d2 = {"deleteIncomingCallLog", "", "context", "Landroid/content/Context;", "incomingNumber", "", "getIncomingNumberByDetails", "details", "Landroid/telecom/Call$Details;", "turnSilent", "HMessagesPrj_prodRelease"}, k = 2, mv = {1, 1, 16})
public final class CallInterceptorKt {
    /* JADX INFO: Access modifiers changed from: private */
    public static final void deleteIncomingCallLog(final Context context, final String incomingNumber) {
        if (ActivityCompat.checkSelfPermission(context, "android.permission.WRITE_CALL_LOG") == 0) {
            final Uri uri = Uri.parse("content://call_log/calls");
            context.getContentResolver().registerContentObserver(uri, true, new ContentObserver(new Handler()) { // from class: im.uwrkaxlmjj.tel.CallInterceptorKt.deleteIncomingCallLog.1
                @Override // android.database.ContentObserver
                public void onChange(boolean selfChange) {
                    super.onChange(selfChange);
                    boolean z = context.getContentResolver().delete(uri, "number=?", new String[]{incomingNumber}) > 0;
                    context.getContentResolver().unregisterContentObserver(this);
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void turnSilent(Context context) {
        try {
            Object systemService = context.getSystemService("audio");
            if (systemService == null) {
                throw new TypeCastException("null cannot be cast to non-null type android.media.AudioManager");
            }
            AudioManager audioManager = (AudioManager) systemService;
            audioManager.getStreamVolume(2);
            audioManager.setStreamVolume(2, 0, 8);
            Object systemService2 = context.getSystemService("notification");
            if (systemService2 == null) {
                throw new TypeCastException("null cannot be cast to non-null type android.app.NotificationManager");
            }
        } catch (Exception e) {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getIncomingNumberByDetails(Call.Details details) {
        Uri handle = details.getHandle();
        Intrinsics.checkExpressionValueIsNotNull(handle, "details.handle");
        String schemeSpecificPart = handle.getSchemeSpecificPart();
        if (schemeSpecificPart == null) {
            try {
                Parcelable par = details.getIntentExtras().getParcelable("android.telecom.extra.INCOMING_CALL_ADDRESS");
                if (par != null) {
                    Uri uri = (Uri) par;
                    return Uri.decode(uri.getSchemeSpecificPart());
                }
                return schemeSpecificPart;
            } catch (Exception e) {
                return schemeSpecificPart;
            }
        }
        return schemeSpecificPart;
    }
}
