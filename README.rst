AWS Robot
=========

* Does your IP change often?
* Does the EC2 instance you are connecting to only accept SSH connections from a whitelist of IPs?
* Do you also have AWS Cli access and just want to automate away the repetitive configuration?


Installation
------------

    pipx install https://github.com/jamesidw/aws-robot.git

That's it! There should now be a `robot` command in your path.

Set up a configuration

    robot config

Grant your IP access

    robot grant

Use `--help` on any of the commands to see options

Assumptions
-----------

* You have installed the AWS CLI...hopefully v2 [v1 also works]
* The profiles(s) you configure will match the AWS profiles
* The profile(s) you configure should have the region configured