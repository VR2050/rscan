package androidx.recyclerview.widget;

import android.content.Context;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes2.dex */
public class LinearScrollOffsetLayoutManager extends LinearLayoutManager {
    private Map<Integer, Integer> heightMap;

    public LinearScrollOffsetLayoutManager(Context context) {
        super(context);
        this.heightMap = new HashMap();
    }

    public LinearScrollOffsetLayoutManager(Context context, int orientation, boolean reverseLayout) {
        super(context, orientation, reverseLayout);
        this.heightMap = new HashMap();
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutCompleted(RecyclerView.State state) {
        super.onLayoutCompleted(state);
        int count = getChildCount();
        for (int i = 0; i < count; i++) {
            View view = getChildAt(i);
            this.heightMap.put(Integer.valueOf(i), Integer.valueOf(view.getHeight()));
        }
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollOffset(RecyclerView.State state) {
        return computeScrollOffset(state);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollOffset(RecyclerView.State state) {
        return computeScrollOffset(state);
    }

    private int computeScrollOffset(RecyclerView.State state) {
        if (getChildCount() == 0) {
            return 0;
        }
        int firstVisiablePosition = findFirstVisibleItemPosition();
        View firstVisiableView = findViewByPosition(firstVisiablePosition);
        int offsetY = -((int) firstVisiableView.getY());
        for (int i = 0; i < firstVisiablePosition; i++) {
            offsetY += this.heightMap.get(Integer.valueOf(i)) == null ? 0 : this.heightMap.get(Integer.valueOf(i)).intValue();
        }
        return offsetY;
    }
}
