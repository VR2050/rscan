package im.uwrkaxlmjj.ui.hui.decoration;

import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import im.uwrkaxlmjj.ui.hui.decoration.BaseItemDecoration;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class BaseItemDecoration<I extends BaseItemDecoration> extends RecyclerView.ItemDecoration {
    protected List<Integer> mExcludeViewTypeList = new ArrayList();

    public int getSpanCount(RecyclerView parent) {
        RecyclerView.LayoutManager layoutManager = parent.getLayoutManager();
        if (layoutManager instanceof GridLayoutManager) {
            return ((GridLayoutManager) layoutManager).getSpanCount();
        }
        if (layoutManager instanceof StaggeredGridLayoutManager) {
            return ((StaggeredGridLayoutManager) layoutManager).getSpanCount();
        }
        return 1;
    }

    public boolean isFirstRow(int position, int columnCount) {
        return position < columnCount;
    }

    public boolean isLastRow(int position, int columnCount, int childCount) {
        if (columnCount == 1) {
            return position + 1 == childCount;
        }
        int lastRawItemCount = childCount % columnCount;
        int rawCount = ((childCount - lastRawItemCount) / columnCount) + (lastRawItemCount > 0 ? 1 : 0);
        int rawPositionJudge = (position + 1) % columnCount;
        if (rawPositionJudge == 0) {
            int rawPosition = (position + 1) / columnCount;
            return rawCount == rawPosition;
        }
        int rawPosition2 = position + 1;
        return rawCount == ((rawPosition2 - rawPositionJudge) / columnCount) + 1;
    }

    public boolean isFirstColumn(int position, int columnCount) {
        return columnCount == 1 || position % columnCount == 0;
    }

    public boolean isLastColumn(int position, int columnCount) {
        return columnCount == 1 || (position + 1) % columnCount == 0;
    }

    public boolean isHorizontal(RecyclerView parent) {
        RecyclerView.LayoutManager manager = parent.getLayoutManager();
        if (manager instanceof LinearLayoutManager) {
            boolean isHorizontal = ((LinearLayoutManager) manager).getOrientation() == 0;
            return isHorizontal;
        }
        boolean isHorizontal2 = manager instanceof StaggeredGridLayoutManager;
        if (isHorizontal2) {
            boolean isHorizontal3 = ((StaggeredGridLayoutManager) manager).getOrientation() == 0;
            return isHorizontal3;
        }
        return false;
    }

    public I setExcludeViewTypeList(int... excludeViewType) {
        for (int i : excludeViewType) {
            this.mExcludeViewTypeList.add(Integer.valueOf(i));
        }
        return this;
    }

    public I setExcludeViewTypeList(List<Integer> excludeViewTypeList) {
        this.mExcludeViewTypeList = excludeViewTypeList;
        return this;
    }

    public List<Integer> getExcludeViewTypeList() {
        return this.mExcludeViewTypeList;
    }
}
