package crypto;

class queueing_model{
	public static void main(String[] args) throws Exception{
		//args[0]: serving time (ms) / each request
		//args[1]: user coming interval (request per second)
		//args[2]: user waiting time (ms) -> set 12 seconds = 12000 milliseconds
		//args[3]: total simulation time (ms)
		int cnt = 0;
		float pointer = 0; //(ms)
		float args0 = Float.parseFloat(args[0]);
		float args1 = 1000/Float.parseFloat(args[1]);
		float args2 = Float.parseFloat(args[2]);
		float args3 = Float.parseFloat(args[3]);
		float n = args3/args1;
		for(int i=0; i<n; i++) {
			float user_waiting_deadline = i*args1+args2;
			if(user_waiting_deadline < pointer) {
				// fail
				cnt++;
			}
			else if(user_waiting_deadline >= pointer) {
				// success
				pointer += args0;
			}
		}
		System.out.println("failure rate: " + cnt*100/n + "%");
		return;
	}
}