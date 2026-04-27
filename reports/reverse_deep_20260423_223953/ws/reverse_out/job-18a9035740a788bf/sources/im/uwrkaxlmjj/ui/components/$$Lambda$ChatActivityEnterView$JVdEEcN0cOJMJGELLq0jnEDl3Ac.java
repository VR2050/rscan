package im.uwrkaxlmjj.ui.components;

import im.uwrkaxlmjj.ui.components.AlertsCreator;

/* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$JVdEEcN0cOJMJGELLq0jnEDl3Ac, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes5.dex */
public final /* synthetic */ class $$Lambda$ChatActivityEnterView$JVdEEcN0cOJMJGELLq0jnEDl3Ac implements AlertsCreator.ScheduleDatePickerDelegate {
    private final /* synthetic */ ChatActivityEnterView f$0;

    public /* synthetic */ $$Lambda$ChatActivityEnterView$JVdEEcN0cOJMJGELLq0jnEDl3Ac(ChatActivityEnterView chatActivityEnterView) {
        this.f$0 = chatActivityEnterView;
    }

    @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
    public final void didSelectDate(boolean z, int i) {
        this.f$0.sendMessageInternal(z, i);
    }
}
