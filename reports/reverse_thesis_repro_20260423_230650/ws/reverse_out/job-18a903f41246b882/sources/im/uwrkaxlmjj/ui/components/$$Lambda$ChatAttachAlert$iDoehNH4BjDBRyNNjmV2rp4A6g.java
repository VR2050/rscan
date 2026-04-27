package im.uwrkaxlmjj.ui.components;

import im.uwrkaxlmjj.ui.components.AlertsCreator;

/* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatAttachAlert$iDoe-hNH4BjDBRyNNjmV2rp4A6g, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes5.dex */
public final /* synthetic */ class $$Lambda$ChatAttachAlert$iDoehNH4BjDBRyNNjmV2rp4A6g implements AlertsCreator.ScheduleDatePickerDelegate {
    private final /* synthetic */ ChatAttachAlert f$0;

    public /* synthetic */ $$Lambda$ChatAttachAlert$iDoehNH4BjDBRyNNjmV2rp4A6g(ChatAttachAlert chatAttachAlert) {
        this.f$0 = chatAttachAlert;
    }

    @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
    public final void didSelectDate(boolean z, int i) {
        this.f$0.sendPressed(z, i);
    }
}
