package im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils;

import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.blankj.utilcode.util.ScreenUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.AutoPlayItemInterface;
import java.util.LinkedHashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes5.dex */
public class AutoPlayTool {
    private AutoPlayItemInterface mHolder;
    private int mode;
    private int visiblePercent;
    public static int MODE_PLAY_FIRST = 0;
    public static int MODE_PLAY_CENTER = 1;

    public AutoPlayTool() {
        this.visiblePercent = 60;
        this.mode = MODE_PLAY_FIRST;
    }

    public AutoPlayTool(int visiblePercent) {
        this.visiblePercent = 60;
        this.mode = MODE_PLAY_FIRST;
        this.visiblePercent = visiblePercent;
    }

    public AutoPlayTool(int visiblePercent, int mode) {
        this.visiblePercent = 60;
        this.mode = MODE_PLAY_FIRST;
        this.visiblePercent = visiblePercent;
        this.mode = mode;
    }

    public void setMode(int mode) {
        this.mode = mode;
    }

    public int onActiveWhenNoScrolling(RecyclerView recyclerView) {
        View view;
        LinearLayoutManager layoutManager = null;
        if (recyclerView.getLayoutManager() instanceof LinearLayoutManager) {
            layoutManager = (LinearLayoutManager) recyclerView.getLayoutManager();
        }
        if (layoutManager != null) {
            int lastItemPosition = layoutManager.findLastVisibleItemPosition();
            LinkedHashMap<Integer, AutoPlayItemInterface> items = new LinkedHashMap<>();
            for (int firstItemPosition = layoutManager.findFirstVisibleItemPosition(); firstItemPosition <= lastItemPosition; firstItemPosition++) {
                Object objFindViewHolderForLayoutPosition = recyclerView.findViewHolderForLayoutPosition(firstItemPosition);
                if ((objFindViewHolderForLayoutPosition instanceof AutoPlayItemInterface) && (view = ((AutoPlayItemInterface) objFindViewHolderForLayoutPosition).getAutoPlayView()) != null && getVisible(view, this.visiblePercent)) {
                    if (this.mode == MODE_PLAY_FIRST) {
                        ((AutoPlayItemInterface) objFindViewHolderForLayoutPosition).setActive();
                        this.mHolder = (AutoPlayItemInterface) objFindViewHolderForLayoutPosition;
                        return firstItemPosition;
                    }
                    items.put(Integer.valueOf(firstItemPosition), (AutoPlayItemInterface) objFindViewHolderForLayoutPosition);
                }
            }
            int d = Integer.MAX_VALUE;
            AutoPlayItemInterface findHolder = null;
            int position = -1;
            for (Map.Entry<Integer, AutoPlayItemInterface> entry : items.entrySet()) {
                int d2 = getDistanceFromCenter(entry.getValue().getAutoPlayView());
                if (d2 < d) {
                    AutoPlayItemInterface findHolder2 = entry.getValue();
                    findHolder = findHolder2;
                    d = d2;
                    position = entry.getKey().intValue();
                }
            }
            AutoPlayItemInterface autoPlayItemInterface = this.mHolder;
            if (autoPlayItemInterface != findHolder) {
                if (autoPlayItemInterface != null) {
                    autoPlayItemInterface.deactivate();
                }
                this.mHolder = findHolder;
            }
            AutoPlayItemInterface autoPlayItemInterface2 = this.mHolder;
            if (autoPlayItemInterface2 != null) {
                autoPlayItemInterface2.setActive();
                return position;
            }
            return -1;
        }
        return -1;
    }

    public void onScrolledAndDeactivate(RecyclerView recyclerView) {
        AutoPlayItemInterface autoPlayItemInterface = this.mHolder;
        if (autoPlayItemInterface != null && autoPlayItemInterface.getAutoPlayView() != null && !getVisible(this.mHolder.getAutoPlayView(), this.visiblePercent)) {
            this.mHolder.deactivate();
        }
    }

    public void onScrolledAndDeactivate() {
        AutoPlayItemInterface autoPlayItemInterface = this.mHolder;
        if (autoPlayItemInterface != null && autoPlayItemInterface.getAutoPlayView() != null && !getVisible(this.mHolder.getAutoPlayView(), this.visiblePercent)) {
            this.mHolder.deactivate();
        }
    }

    public void onRefreshDeactivate() {
        AutoPlayItemInterface autoPlayItemInterface = this.mHolder;
        if (autoPlayItemInterface != null && autoPlayItemInterface.getAutoPlayView() != null) {
            this.mHolder.deactivate();
            this.mHolder = null;
        }
    }

    public void onDeactivate() {
        AutoPlayItemInterface autoPlayItemInterface = this.mHolder;
        if (autoPlayItemInterface != null && autoPlayItemInterface.getAutoPlayView() != null) {
            this.mHolder.deactivate();
        }
    }

    public void setVisiblePercent(int visiblePercent) {
        this.visiblePercent = visiblePercent;
    }

    private int getVisiblePercent(View v) {
        Rect r = new Rect();
        boolean visible = v.getLocalVisibleRect(r);
        if (visible && v.getMeasuredHeight() > 0) {
            int percent = (r.height() * 100) / v.getMeasuredHeight();
            return percent;
        }
        return -1;
    }

    private boolean getVisible(View v, int value) {
        Rect r = new Rect();
        boolean visible = v.getLocalVisibleRect(r);
        if (!visible || v.getVisibility() != 0 || getVisiblePercent(v) < value) {
            return false;
        }
        return true;
    }

    private int getDistanceFromCenter(View view) {
        int centerHeight = (int) (((double) ScreenUtils.getScreenHeight()) / 2.3d);
        int[] viewLocation = new int[2];
        view.getLocationOnScreen(viewLocation);
        return Math.abs((viewLocation[1] + (view.getHeight() / 2)) - centerHeight);
    }
}
