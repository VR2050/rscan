package com.lljjcoder.style.citylist.Toast;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;
import com.lljjcoder.style.citypickerview.C3949R;

/* loaded from: classes2.dex */
public class AlarmDailog extends Toast {
    private Context context;
    private TextView noticeText;
    private Toast toast;

    public AlarmDailog(Context context) {
        super(context);
        this.context = context;
        View inflate = LayoutInflater.from(context).inflate(C3949R.layout.dialog_alarm_ui, (ViewGroup) null);
        this.noticeText = (TextView) inflate.findViewById(C3949R.id.noticeText);
        Toast toast = new Toast(context);
        this.toast = toast;
        toast.setGravity(17, 0, 0);
        this.toast.setDuration(0);
        this.toast.setView(inflate);
    }

    public void setShowText(String str) {
        this.noticeText.setText(str);
    }

    @Override // android.widget.Toast
    public void show() {
        this.toast.show();
    }
}
