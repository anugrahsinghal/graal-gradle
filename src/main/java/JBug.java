public class JBug {
	public static void main(String[] args) {
		System.out.println("Hello Graal");

		var toolingApi = new JToolingApi();

		var allProjects = toolingApi.findAllProjects(System.getenv("HOME") + "/personal/Signal-Android");

		allProjects.forEach(project -> System.out.printf("Path: '%s' --> Directory: '%s'", project.getPath(), project.getProjectDirectory().getPath()));

	}
}
