package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.RecyclerView.ViewHolder;
import im.uwrkaxlmjj.messenger.R;

/* JADX INFO: loaded from: classes5.dex */
public class AddPictureRecyclerView<T, VH extends RecyclerView.ViewHolder> extends RecyclerView {
    private RecyItemTouchHelperCallBack<T, VH> callBack;
    private DragListener<T, VH> dragListener;
    private ItemTouchHelper itemTouchHelper;
    private AddPictureTouchAdapter<T, VH> mAdapter;
    private int maxCount;
    private boolean moveEnable;
    private boolean nestedScrollEnable;
    private OnRecyclerItemTouchListener<VH> onRecyclerItemTouchListener;

    public AddPictureRecyclerView(Context context) {
        this(context, null);
    }

    public AddPictureRecyclerView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public AddPictureRecyclerView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        init(attrs);
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
    }

    private void init(AttributeSet attrs) {
        TypedArray mTypedArray = getContext().obtainStyledAttributes(attrs, R.styleable.AddPictureRecyclerView);
        this.maxCount = mTypedArray.getInteger(0, 9);
        this.moveEnable = mTypedArray.getBoolean(1, true);
        this.nestedScrollEnable = mTypedArray.getBoolean(2, false);
        mTypedArray.recycle();
        setNestedScrollingEnabled(this.nestedScrollEnable);
        setLayoutManager(new GridLayoutManager(getContext(), 3, 1, false));
        if (this.moveEnable) {
            setClipChildren(false);
        }
        initTouchHelper();
    }

    private void initTouchHelper() {
        if (this.moveEnable) {
            initRecyclerItemTouch();
            addOnItemTouchListener(this.onRecyclerItemTouchListener);
        }
    }

    private void initRecyclerItemTouch() {
        if (this.onRecyclerItemTouchListener == null) {
            this.onRecyclerItemTouchListener = (OnRecyclerItemTouchListener<VH>) new OnRecyclerItemTouchListener<VH>(this) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.AddPictureRecyclerView.1
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.OnRecyclerItemTouchListener
                public void onItemClick(VH vh) {
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.OnRecyclerItemTouchListener
                public void onItemLongClick(VH vh) {
                    if (vh != null && AddPictureRecyclerView.this.dragListener != null && AddPictureRecyclerView.this.mAdapter != null && AddPictureRecyclerView.this.dragListener.canDrag(vh, vh.getAdapterPosition(), AddPictureRecyclerView.this.mAdapter.getItem(vh.getAdapterPosition())) && AddPictureRecyclerView.this.itemTouchHelper != null) {
                        AddPictureRecyclerView.this.itemTouchHelper.startDrag(vh);
                    }
                }
            };
        }
        addOnItemTouchListener(this.onRecyclerItemTouchListener);
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void setAdapter(RecyclerView.Adapter adapter) {
        if (!(adapter instanceof AddPictureTouchAdapter)) {
            throw new IllegalArgumentException("Must set AddPictureTouchAdapter");
        }
        this.mAdapter = (AddPictureTouchAdapter) adapter;
        setMaxCount(this.maxCount);
        super.setAdapter(adapter);
        setTouchHelperCallBack();
    }

    private void setTouchHelperCallBack() {
        if (this.moveEnable) {
            this.callBack = new RecyItemTouchHelperCallBack<>(this.mAdapter);
            setDragListener();
            ItemTouchHelper itemTouchHelper = new ItemTouchHelper(this.callBack);
            this.itemTouchHelper = itemTouchHelper;
            itemTouchHelper.attachToRecyclerView(this);
        }
    }

    private void setDragListener() {
        RecyItemTouchHelperCallBack<T, VH> recyItemTouchHelperCallBack = this.callBack;
        if (recyItemTouchHelperCallBack != null) {
            recyItemTouchHelperCallBack.setDragListener(this.dragListener);
        }
    }

    public void setDragListener(DragListener<T, VH> dragListener) {
        this.dragListener = dragListener;
        setDragListener();
    }

    public void setItemTouchHelperCallBack(RecyItemTouchHelperCallBack<T, VH> callBack) {
        this.callBack = callBack;
    }

    public RecyItemTouchHelperCallBack<T, VH> getItemTouchHelperCallBack() {
        return this.callBack;
    }

    public void setMaxCount(int maxCount) {
        this.maxCount = maxCount;
        AddPictureTouchAdapter<T, VH> addPictureTouchAdapter = this.mAdapter;
        if (addPictureTouchAdapter != null) {
            addPictureTouchAdapter.setMaxCount(maxCount);
        }
    }

    public int getMaxCount() {
        return this.maxCount;
    }
}
