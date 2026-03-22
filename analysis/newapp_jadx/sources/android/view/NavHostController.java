package android.view;

import android.content.Context;
import androidx.activity.OnBackPressedDispatcher;
import androidx.annotation.NonNull;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.ViewModelStore;

/* loaded from: classes.dex */
public class NavHostController extends NavController {
    public NavHostController(@NonNull Context context) {
        super(context);
    }

    @Override // android.view.NavController
    public final void enableOnBackPressed(boolean z) {
        super.enableOnBackPressed(z);
    }

    @Override // android.view.NavController
    public final void setLifecycleOwner(@NonNull LifecycleOwner lifecycleOwner) {
        super.setLifecycleOwner(lifecycleOwner);
    }

    @Override // android.view.NavController
    public final void setOnBackPressedDispatcher(@NonNull OnBackPressedDispatcher onBackPressedDispatcher) {
        super.setOnBackPressedDispatcher(onBackPressedDispatcher);
    }

    @Override // android.view.NavController
    public final void setViewModelStore(@NonNull ViewModelStore viewModelStore) {
        super.setViewModelStore(viewModelStore);
    }
}
