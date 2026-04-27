package im.uwrkaxlmjj.ui;

import im.uwrkaxlmjj.ui.components.AlertsCreator;

/* JADX INFO: renamed from: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$1AbJq_Bmo4eP2llPycO8mQRGlkU, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes5.dex */
public final /* synthetic */ class $$Lambda$PhotoViewer$1AbJq_Bmo4eP2llPycO8mQRGlkU implements AlertsCreator.ScheduleDatePickerDelegate {
    private final /* synthetic */ PhotoViewer f$0;

    public /* synthetic */ $$Lambda$PhotoViewer$1AbJq_Bmo4eP2llPycO8mQRGlkU(PhotoViewer photoViewer) {
        this.f$0 = photoViewer;
    }

    @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
    public final void didSelectDate(boolean z, int i) {
        this.f$0.sendPressed(z, i);
    }
}
