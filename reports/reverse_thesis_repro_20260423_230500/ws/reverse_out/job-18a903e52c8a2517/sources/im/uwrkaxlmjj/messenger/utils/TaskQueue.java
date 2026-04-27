package im.uwrkaxlmjj.messenger.utils;

/* JADX INFO: loaded from: classes2.dex */
public class TaskQueue<T> {
    private TaskQueue<T>.DataNode pHeader = null;
    private TaskQueue<T>.DataNode pTail = null;
    private int miCount = 0;

    public synchronized boolean inputQueue(T tMember) {
        if (tMember == null) {
            return false;
        }
        TaskQueue<T>.DataNode dataNode = new DataNode(tMember);
        if (this.miCount == 0) {
            this.pHeader = dataNode;
            this.pTail = dataNode;
        } else {
            ((DataNode) this.pTail).mNextNode = dataNode;
        }
        this.pTail = dataNode;
        this.miCount++;
        return true;
    }

    public synchronized T getQueueTask() {
        TaskQueue<T>.DataNode dataNode = null;
        if (this.pHeader != null) {
            dataNode = this.pHeader;
            this.pHeader = ((DataNode) dataNode).mNextNode;
            ((DataNode) dataNode).mNextNode = null;
            this.miCount--;
        }
        if (dataNode == null) {
            return null;
        }
        return (T) ((DataNode) dataNode).mData;
    }

    public synchronized void cleanQueue() {
        while (this.pHeader != null) {
            TaskQueue<T>.DataNode dataNode = this.pHeader;
            this.pHeader = ((DataNode) dataNode).mNextNode;
            ((DataNode) dataNode).mNextNode = null;
        }
        this.miCount = 0;
    }

    public int getQueueSize() {
        return this.miCount;
    }

    private class DataNode {
        private T mData;
        private TaskQueue<T>.DataNode mNextNode = null;

        public DataNode(T t) {
            this.mData = t;
        }
    }
}
