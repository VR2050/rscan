package im.uwrkaxlmjj.ui.components.paint;

import im.uwrkaxlmjj.messenger.AndroidUtilities;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/* JADX INFO: loaded from: classes5.dex */
public class UndoStore {
    private UndoStoreDelegate delegate;
    private Map<UUID, Runnable> uuidToOperationMap = new HashMap();
    private List<UUID> operations = new ArrayList();

    public interface UndoStoreDelegate {
        void historyChanged();
    }

    public boolean canUndo() {
        return !this.operations.isEmpty();
    }

    public void setDelegate(UndoStoreDelegate undoStoreDelegate) {
        this.delegate = undoStoreDelegate;
    }

    public void registerUndo(UUID uuid, Runnable undoRunnable) {
        this.uuidToOperationMap.put(uuid, undoRunnable);
        this.operations.add(uuid);
        notifyOfHistoryChanges();
    }

    public void unregisterUndo(UUID uuid) {
        this.uuidToOperationMap.remove(uuid);
        this.operations.remove(uuid);
        notifyOfHistoryChanges();
    }

    public void undo() {
        if (this.operations.size() == 0) {
            return;
        }
        int lastIndex = this.operations.size() - 1;
        UUID uuid = this.operations.get(lastIndex);
        Runnable undoRunnable = this.uuidToOperationMap.get(uuid);
        this.uuidToOperationMap.remove(uuid);
        this.operations.remove(lastIndex);
        undoRunnable.run();
        notifyOfHistoryChanges();
    }

    public void reset() {
        this.operations.clear();
        this.uuidToOperationMap.clear();
        notifyOfHistoryChanges();
    }

    private void notifyOfHistoryChanges() {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.UndoStore.1
            @Override // java.lang.Runnable
            public void run() {
                if (UndoStore.this.delegate != null) {
                    UndoStore.this.delegate.historyChanged();
                }
            }
        });
    }
}
