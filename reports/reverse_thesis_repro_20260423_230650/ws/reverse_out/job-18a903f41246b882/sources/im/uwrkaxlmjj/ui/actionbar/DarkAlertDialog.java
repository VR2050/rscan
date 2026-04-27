package im.uwrkaxlmjj.ui.actionbar;

import android.content.Context;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;

/* JADX INFO: loaded from: classes5.dex */
public class DarkAlertDialog extends AlertDialog {
    public DarkAlertDialog(Context context, int progressStyle) {
        super(context, progressStyle);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0034  */
    @Override // im.uwrkaxlmjj.ui.actionbar.AlertDialog
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected int getThemeColor(java.lang.String r6) {
        /*
            r5 = this;
            int r0 = r6.hashCode()
            r1 = 3
            r2 = 2
            r3 = 1
            r4 = -1
            switch(r0) {
                case -1849805674: goto L2a;
                case -451706526: goto L20;
                case -93324646: goto L16;
                case 1828201066: goto Lc;
                default: goto Lb;
            }
        Lb:
            goto L34
        Lc:
            java.lang.String r0 = "dialogTextBlack"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lb
            r0 = 1
            goto L35
        L16:
            java.lang.String r0 = "dialogButton"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lb
            r0 = 2
            goto L35
        L20:
            java.lang.String r0 = "dialogScrollGlow"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lb
            r0 = 3
            goto L35
        L2a:
            java.lang.String r0 = "dialogBackground"
            boolean r0 = r6.equals(r0)
            if (r0 == 0) goto Lb
            r0 = 0
            goto L35
        L34:
            r0 = -1
        L35:
            if (r0 == 0) goto L43
            if (r0 == r3) goto L42
            if (r0 == r2) goto L42
            if (r0 == r1) goto L42
            int r0 = super.getThemeColor(r6)
            return r0
        L42:
            return r4
        L43:
            r0 = -14277082(0xffffffffff262626, float:-2.2084993E38)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.actionbar.DarkAlertDialog.getThemeColor(java.lang.String):int");
    }

    public static class Builder extends AlertDialog.Builder {
        public Builder(Context context) {
            super(new DarkAlertDialog(context, 0));
        }

        public Builder(Context context, int progressViewStyle) {
            super(new DarkAlertDialog(context, progressViewStyle));
        }
    }
}
