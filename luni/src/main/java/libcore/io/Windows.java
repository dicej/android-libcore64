package libcore.io;

public class Windows extends ForwardingOs {

	public Windows() {
		super(new Posix());
	}
	
	public native boolean pathIsRelative(String path);

}
