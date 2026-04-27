package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview;

import android.graphics.Canvas;
import android.os.Vibrator;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.RecyclerView.ViewHolder;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RecyItemTouchHelperCallBack<T, VH extends RecyclerView.ViewHolder> extends ItemTouchHelper.Callback {
    public static final float ALPHA_FULL = 1.0f;
    private boolean actionUp;
    private DragListener<T, VH> dragListener;
    private boolean isSwipeEnable = false;
    private ItemTouchAdapter<T, VH> mAdapter;

    public RecyItemTouchHelperCallBack(ItemTouchAdapter<T, VH> adapter) {
        this.mAdapter = adapter;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public int getMovementFlags(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
        if (recyclerView.getLayoutManager() instanceof GridLayoutManager) {
            return makeMovementFlags(15, 0);
        }
        return makeMovementFlags(3, 48);
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public boolean onMove(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder, RecyclerView.ViewHolder target) {
        int fromPosition = viewHolder.getAdapterPosition();
        int toPosition = target.getAdapterPosition();
        if (!checkCanLongDrag(fromPosition, toPosition)) {
            return false;
        }
        DragListener<T, VH> dragListener = this.dragListener;
        if (dragListener != null) {
            dragListener.onDraging();
        }
        ItemTouchAdapter<T, VH> itemTouchAdapter = this.mAdapter;
        if (itemTouchAdapter != null) {
            itemTouchAdapter.onItemMove(fromPosition, toPosition);
            return true;
        }
        return true;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onSwiped(RecyclerView.ViewHolder viewHolder, int direction) {
        ItemTouchAdapter<T, VH> itemTouchAdapter = this.mAdapter;
        if (itemTouchAdapter != null) {
            itemTouchAdapter.onItemRemove(viewHolder.getAdapterPosition());
        }
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onChildDraw(Canvas c, RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder, float dX, float dY, int actionState, boolean isCurrentlyActive) {
        DragListener<T, VH> dragListener = this.dragListener;
        if (dragListener != null) {
            boolean isInArea = dragListener.checkIsInSpecialArea(c, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive);
            boolean userSelfDo = this.dragListener.stateIsInSpecialArea(isInArea, this.actionUp, viewHolder.getAdapterPosition());
            if (userSelfDo || !isInArea || !this.actionUp) {
                this.dragListener.stateIsInSpecialArea(isInArea, this.actionUp, viewHolder.getAdapterPosition());
            } else {
                viewHolder.itemView.setVisibility(4);
                ItemTouchAdapter<T, VH> itemTouchAdapter = this.mAdapter;
                if (itemTouchAdapter != null) {
                    itemTouchAdapter.onItemRemove(viewHolder.getAdapterPosition());
                }
                this.dragListener.doBothInAreaAndFingerUp(true, this.actionUp);
                this.actionUp = false;
                return;
            }
        }
        if (actionState == 1) {
            View itemView = viewHolder.itemView;
            float alpha = 1.0f - (Math.abs(dX) / itemView.getWidth());
            itemView.setAlpha(alpha);
        }
        super.onChildDraw(c, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive);
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public long getAnimationDuration(RecyclerView recyclerView, int animationType, float animateDx, float animateDy) {
        this.actionUp = true;
        return super.getAnimationDuration(recyclerView, animationType, animateDx, animateDy);
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onSelectedChanged(RecyclerView.ViewHolder viewHolder, int actionState) {
        Vibrator vibrator;
        if (viewHolder != null && checkCanLongDrag(viewHolder.getAdapterPosition(), -1) && actionState != 0) {
            ItemTouchAdapter<T, VH> itemTouchAdapter = this.mAdapter;
            if (itemTouchAdapter != null && itemTouchAdapter.getContext() != null && (vibrator = (Vibrator) this.mAdapter.getContext().getSystemService("vibrator")) != null) {
                vibrator.vibrate(50L);
            }
            DragListener<T, VH> dragListener = this.dragListener;
            if (dragListener != null) {
                dragListener.onPreDrag();
            }
            startItemScaleAni(viewHolder, true);
        }
        super.onSelectedChanged(viewHolder, actionState);
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void clearView(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
        super.clearView(recyclerView, viewHolder);
        startItemScaleAni(viewHolder, false);
        viewHolder.itemView.setAlpha(1.0f);
        viewHolder.itemView.setBackgroundColor(-1);
        resetDragListenerBoth();
        DragListener<T, VH> dragListener = this.dragListener;
        if (dragListener != null) {
            dragListener.onReleasedDrag();
            this.dragListener.clearView();
        }
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public boolean isLongPressDragEnabled() {
        return false;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public boolean isItemViewSwipeEnabled() {
        return this.isSwipeEnable;
    }

    private void resetDragListenerBoth() {
        DragListener<T, VH> dragListener = this.dragListener;
        if (dragListener != null) {
            dragListener.stateIsInSpecialArea(false, false, -1);
        }
        this.actionUp = false;
    }

    public void startItemScaleAni(RecyclerView.ViewHolder viewHolder, boolean bigger) {
        if (viewHolder != null) {
            if (bigger) {
                doScaleAni(viewHolder.itemView, R.anim.scale_from_100_to_110, false);
            } else {
                doScaleAni(viewHolder.itemView, R.anim.scale_from_110_to_100, true);
            }
        }
    }

    public boolean checkCanLongDrag(int fromOrLongClickPosition, int toPosition) {
        ItemTouchAdapter<T, VH> itemTouchAdapter = this.mAdapter;
        return itemTouchAdapter == null || itemTouchAdapter.getCannotDragIndexList() == null || (!this.mAdapter.getCannotDragIndexList().contains(Integer.valueOf(fromOrLongClickPosition)) && (-1 == toPosition || !this.mAdapter.getCannotDragIndexList().contains(Integer.valueOf(toPosition))));
    }

    public void setSwipeEnable(boolean swipeEnable) {
        this.isSwipeEnable = swipeEnable;
    }

    public void setDragListener(DragListener<T, VH> dragListener) {
        this.dragListener = dragListener;
    }

    public void doScaleAni(final View view, int animResId, boolean clearAnimation) {
        if (view == null) {
            return;
        }
        Animation animation = AnimationUtils.loadAnimation(view.getContext(), animResId);
        if (clearAnimation) {
            animation.setAnimationListener(new Animation.AnimationListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.RecyItemTouchHelperCallBack.1
                @Override // android.view.animation.Animation.AnimationListener
                public void onAnimationStart(Animation animation2) {
                }

                @Override // android.view.animation.Animation.AnimationListener
                public void onAnimationEnd(Animation animation2) {
                    view.clearAnimation();
                }

                @Override // android.view.animation.Animation.AnimationListener
                public void onAnimationRepeat(Animation animation2) {
                }
            });
        }
        view.startAnimation(animation);
    }
}
