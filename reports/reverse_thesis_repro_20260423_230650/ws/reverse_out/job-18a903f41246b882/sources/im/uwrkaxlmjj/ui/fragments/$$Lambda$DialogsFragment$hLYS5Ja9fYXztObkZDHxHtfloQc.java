package im.uwrkaxlmjj.ui.fragments;

import android.content.SharedPreferences;

/* JADX INFO: renamed from: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$hLYS5Ja9fYXztObkZDHxHtfloQc, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes5.dex */
public final /* synthetic */ class $$Lambda$DialogsFragment$hLYS5Ja9fYXztObkZDHxHtfloQc implements SharedPreferences.OnSharedPreferenceChangeListener {
    private final /* synthetic */ DialogsFragment f$0;

    public /* synthetic */ $$Lambda$DialogsFragment$hLYS5Ja9fYXztObkZDHxHtfloQc(DialogsFragment dialogsFragment) {
        this.f$0 = dialogsFragment;
    }

    @Override // android.content.SharedPreferences.OnSharedPreferenceChangeListener
    public final void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String str) {
        this.f$0.onSharedPreferenceChanged(sharedPreferences, str);
    }
}
