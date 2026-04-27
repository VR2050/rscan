package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview;

import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import androidx.core.view.GestureDetectorCompat;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.RecyclerView.ViewHolder;

/* JADX INFO: loaded from: classes5.dex */
public abstract class OnRecyclerItemTouchListener<VH extends RecyclerView.ViewHolder> implements RecyclerView.OnItemTouchListener {
    private GestureDetectorCompat mGestureDetector;
    private RecyclerView recyclerView;

    public abstract void onItemClick(VH vh);

    public abstract void onItemLongClick(VH vh);

    public OnRecyclerItemTouchListener(RecyclerView recyclerView) {
        this.recyclerView = recyclerView;
        this.mGestureDetector = new GestureDetectorCompat(recyclerView.getContext(), new ItemTouchHelperGestureListener());
    }

    @Override // androidx.recyclerview.widget.RecyclerView.OnItemTouchListener
    public boolean onInterceptTouchEvent(RecyclerView rv, MotionEvent e) {
        this.mGestureDetector.onTouchEvent(e);
        return false;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.OnItemTouchListener
    public void onTouchEvent(RecyclerView rv, MotionEvent e) {
        this.mGestureDetector.onTouchEvent(e);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.OnItemTouchListener
    public void onRequestDisallowInterceptTouchEvent(boolean disallowIntercept) {
    }

    private class ItemTouchHelperGestureListener extends GestureDetector.SimpleOnGestureListener {
        private ItemTouchHelperGestureListener() {
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
        public boolean onSingleTapUp(MotionEvent e) {
            View child = OnRecyclerItemTouchListener.this.recyclerView.findChildViewUnder(e.getX(), e.getY());
            if (child != null) {
                RecyclerView.ViewHolder vh = OnRecyclerItemTouchListener.this.recyclerView.getChildViewHolder(child);
                OnRecyclerItemTouchListener.this.onItemClick(vh);
                return true;
            }
            return true;
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
        public void onLongPress(MotionEvent e) {
            View child = OnRecyclerItemTouchListener.this.recyclerView.findChildViewUnder(e.getX(), e.getY());
            if (child != null) {
                RecyclerView.ViewHolder vh = OnRecyclerItemTouchListener.this.recyclerView.getChildViewHolder(child);
                OnRecyclerItemTouchListener.this.onItemLongClick(vh);
            }
        }
    }
}
