package im.uwrkaxlmjj.ui.hui.sysnotify;

import android.os.Bundle;
import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.view.View;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;

/* JADX INFO: loaded from: classes5.dex */
public class SysNotifyAtTextClickableSpan extends ClickableSpan {
    public BaseFragment mBaseFragment;
    public int mUserId;

    public SysNotifyAtTextClickableSpan(int userid, BaseFragment baseFragment) {
        this.mUserId = userid;
        this.mBaseFragment = baseFragment;
    }

    @Override // android.text.style.ClickableSpan
    public void onClick(View widget) {
        Bundle bundle = new Bundle();
        bundle.putInt("user_id", this.mUserId);
        this.mBaseFragment.presentFragment(new NewProfileActivity(bundle));
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint ds) {
        ds.setUnderlineText(false);
    }
}
