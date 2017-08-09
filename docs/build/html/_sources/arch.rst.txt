Architecture of the Palo Alto CFT Lambda Functions
==================================================
.. image:: aws.png

|
|
|

.. graphviz::

    digraph {
        size ="8.4";
        launch_cft [shape=box];
        launch_cft -> init [weight=8, label="deploy init_lambda"]
        init_lambda -> sched_evt1 [weight=8, label="deploy"]
        launch_cft -> eni [weight=8, label="deploy add_eni lambda"]
        sched_evt1 -> check_ilb [weight=8, label="check ilb ips"]
        check_ilb -> delete_asg [weight=8, label="ip deleted"]
        check_ilb -> create_asg [weight=8, label="new ip found"]
        add_eni -> create_eni [weight=8]
        create_eni -> attach_eni_trust [weight=8, label="1. to instance"]
        create_eni -> attach_eni_mgmt [weight=8, label="2. to instance"]
        create_eni -> metrics [weight=8, label="3. deploy metrics lambda"]
        metrics_lambda -> firewall [weight=8, label="retrieve metrics"]
        metrics_lambda -> cloud_watch [weight=8, label="register metrics"]
    }